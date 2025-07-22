import logging
import secrets
from Crypto.Cipher import DES3, DES
from io import BytesIO
from .const import const
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from math import ceil

logger = logging.getLogger("SCP03")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t%(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


class SCP03:
    def __init__(self, card_connection, static_enc, static_mac, static_dek, i_param):
        self.card_connection = card_connection
        self.sec_level = 0

        self.static_enc = static_enc
        self.static_mac = static_mac
        self.static_dek = static_dek
        self.i_param = i_param

        self.session_enc = None
        self.session_mac = None

        self.last_mac = None
        self.encryption_counter = 0
        self.is_mutually_authenticated = False

    def send_secure_apdu(self, command):
        # TODO: Ensure command's logical channel matches the secure channel's
        if command[:3] == [0x00, 0xA4, 0x04]:  # SELECT APDU
            logger.info(
                "SELECT APDU received. Session security level reset to 'No Security'."
            )
            self.reset_session()

        cla, ins, p1, p2, lc = command[:5]
        data = command[5:]

        mac = []
        encrypted_data = data

        # Encrypt data if encryption is required
        if data and (self.sec_level & const.SCP_SECLEVEL_C_DECRYPTION):
            padded = bytes(self._pad_80(data))
            iv = self.encryption_counter.to_bytes(AES.block_size, "big")
            cipher = AES.new(self.session_enc, AES.MODE_CBC, iv)
            encrypted_data = list(cipher.encrypt(padded))

        # Calculate MAC if MAC is required
        if self.sec_level & const.SCP_SECLEVEL_C_MAC:
            mac_input = [
                cla | 0x04,
                ins,
                p1,
                p2,
                len(encrypted_data) + self.mac_len,
            ] + encrypted_data
            mac = self._calc_mac(mac_input)

        # Build secure APDU
        if self.sec_level == const.SCP_SECLEVEL_NO_SECURITY_LEVEL:
            secure_command = command
        else:
            secure_cla = cla | 0x04
            body = encrypted_data + mac
            secure_lc = len(body)
            secure_command = [secure_cla, ins, p1, p2, secure_lc] + body

        # Encryption Counter is encrypted for each command sent within the secure channel, irrespective
        # of whether the command is encrypted or not. In the other words, tranmission of commands that
        # do not have any data field to be encrypted will also increments the counter.
        if self.is_mutually_authenticated:
            self.encryption_counter += 1

        return self.card_connection.send_apdu(secure_command)

    def _pad_80(self, data_list):
        remainder = len(data_list) % 16
        padding_length = (16 - remainder) or 16
        return data_list + [0x80] + ([0x00] * (padding_length - 1))

    def _calc_mac(self, command):
        dtbs = self.mac_chain + bytes(command)

        cmac = CMAC.new(self.session_mac, ciphermod=AES)
        cmac.update(dtbs)
        self.mac_chain = cmac.digest()

        return list(self.mac_chain)[: self.mac_len]

    def external_authenticate(self, sec_level):

        host_cryptogram_bit_length = self.challenges_len * 8
        host_cryptogram_derivation_data = (
            b"\x00" * 11
            + const.SCP03_GP_DERIVATION_CONST_HOST_CRYPTOGRAM
            + const.SCP03_GP_SEPARATION_INDICATOR
            + host_cryptogram_bit_length.to_bytes(2, "big")
            + b"\x01"
            + self.host_challenge
            + self.card_challenge
        )

        cmac = CMAC.new(self.session_mac, ciphermod=AES)
        cmac.update(host_cryptogram_derivation_data)
        host_cryptogram = cmac.digest()[: self.challenges_len]

        # Lc includes an additional 8 or 16 bytes reserved for the MAC
        apdu_without_mac = [
            0x84,
            0x82,
            sec_level,
            0x00,
            self.challenges_len + self.mac_len,
        ] + list(host_cryptogram)

        mac = self._calc_mac(apdu_without_mac)
        external_auth_apdu = apdu_without_mac + mac

        _, sw1, sw2 = self.card_connection.send_apdu(external_auth_apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            self.sec_level = sec_level
            self.encryption_counter = 1
            self.is_mutually_authenticated = True
            return True
        else:
            if sw1 == 0x69 and sw2 == 0x85:  # Condition of Use Not Satisfied
                logger.error(
                    "EXT AUTH failed with 6985: Possibly due to the requested Sec-Level; because INIT UPDATE was OK."
                )
            else:
                logger.error("Ext AUTH failed!")

            return False

    def _calc_session_keys(self):
        """
        Derives session encryption and MAC keys according to GlobalPlatform SCP03 specification.

        Derivation Data Format:
            - 11 bytes of zeros
            - 1 byte derivation constant (ENC or MAC)
            - 1 byte separator "\x00"
            - 2 bytes L (bit length of the derived key)
            - 1 byte counter (value: 1 or 2)
            - context = host_challenge || card_challenge

        L values:
            - 0x0080 for AES-128
            - 0x00C0 for AES-192
            - 0x0100 for AES-256
        """

        key_bit_length = len(self.static_enc) * 8
        L = key_bit_length.to_bytes(2, "big")
        context = self.host_challenge + self.card_challenge
        num_iterations = ceil(len(self.static_enc) / 16)

        session_enc = b""
        session_mac = b""

        for i in range(1, num_iterations + 1):
            counter = i.to_bytes(1, "big")

            enc_derivation_data = (
                b"\x00" * 11
                + const.SCP03_GP_DERIVATION_CONST_ENC_SESSION_KEY
                + const.SCP03_GP_SEPARATION_INDICATOR
                + L
                + counter
                + context
            )

            cmac = CMAC.new(self.static_enc, ciphermod=AES)
            cmac.update(enc_derivation_data)
            session_enc += cmac.digest()

            mac_derivation_data = (
                b"\x00" * 11
                + const.SCP03_GP_DERIVATION_CONST_MAC_SESSION_KEY
                + const.SCP03_GP_SEPARATION_INDICATOR
                + L
                + counter
                + context
            )

            cmac = CMAC.new(self.static_enc, ciphermod=AES)
            cmac.update(mac_derivation_data)
            session_mac += cmac.digest()

        self.session_enc = session_enc
        self.session_mac = session_mac

        logger.debug(
            f"Static ENC: {self.static_enc.hex()}, Static MAC: {self.static_mac.hex()}, Static DEK: {self.static_dek.hex()}"
        )
        logger.debug(
            f"Session ENC: {self.session_enc.hex()}, Session MAC: {self.session_mac.hex()}, Session DEK: NA"
        )

    def initialize_update(self):
        self.reset_session()

        # ToDo: not sure what shall I do when we have multiple entries in i_params!
        self.challenges_len = 16 if self.i_param & 0x01 == 0x01 else 8  # s8/s16 mode
        self.mac_len = self.challenges_len

        self.host_challenge = secrets.token_bytes(self.challenges_len)
        self.host_challenge = bytes.fromhex("AC0C5EFFBFC1E314")

        init_update_apdu = [
            0x80,
            0x50,
            0x00,
            0x00,
            len(self.host_challenge),
        ] + list(self.host_challenge)

        resp_data, sw1, sw2 = self.card_connection.send_apdu(init_update_apdu)

        if (sw1, sw2) != (0x90, 0x00):
            logger.error(f"Unexpected INIT UPDATE APDU response SW: {sw1:02x}{sw2:02x}")

        if (self.challenges_len == 8 and len(resp_data) not in (29, 32)) or (
            self.challenges_len == 16 and len(resp_data) not in (45, 48)
        ):
            logger.error("Unexpected INIT UPDATE APDU response length.")
            return False

        resp_data_byte_stream = BytesIO(bytes(resp_data))

        _ = resp_data_byte_stream.read(10)  # diversification_data
        key_information = resp_data_byte_stream.read(3)
        self.card_challenge = resp_data_byte_stream.read(self.challenges_len)
        card_cryptogram = resp_data_byte_stream.read(self.challenges_len)
        self.sequence_counter = resp_data_byte_stream.read(
            3
        )  # could be empty, as this part is conditional

        # ToDo: check KeyInformation and SCP Proto consistency

        self._calc_session_keys()
        card_cryptogram_bit_length = self.challenges_len * 8
        card_cryptogram_derivation_data = (
            b"\x00" * 11
            + const.SCP03_GP_DERIVATION_CONST_CARD_CRYPTOGRAM
            + const.SCP03_GP_SEPARATION_INDICATOR
            + card_cryptogram_bit_length.to_bytes(2, "big")
            + b"\x01"
            + self.host_challenge
            + self.card_challenge
        )

        cmac = CMAC.new(self.session_mac, ciphermod=AES)
        cmac.update(card_cryptogram_derivation_data)
        expected_card_cryptogram = cmac.digest()[: self.mac_len]

        # Let's verify INIT UPDATE response
        if expected_card_cryptogram != card_cryptogram:
            logger.error("Unexpected Card Cryptogram! Wrong ISD Keys! Stop Trying!")
            return False

        return True

    def reset_session(self):
        self.sec_level = 0
        self.session_enc = None
        self.session_mac = None
        self.mac_chain = b"\x00" * 16
        self.encryption_counter = 0
        self.is_mutually_authenticated = False
