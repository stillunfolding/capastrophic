import logging
import secrets
from Crypto.Cipher import DES3, DES
from .const import const


logger = logging.getLogger("SCP02")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t%(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


class SCP02:
    def __init__(self, card_connection, static_enc, static_mac, static_dek):
        self.card_connection = card_connection
        self.sec_level = 0

        self.static_enc = static_enc
        self.static_mac = static_mac
        self.static_dek = static_dek

        self.session_enc = None
        self.session_mac = None
        self.session_dek = None

        self.last_mac = None

    def send_secure_apdu(self, command):
        # ToDo: command's logical channel shall be compared with the secure channel's logical channel
        if command[:3] == [0x00, 0xA4, 0x04]:  # Select APDU
            logger.info(
                "SELECT APDU received. Secure channel session security level reset to 'No Security'"
            )
            self.reset_session()

        cla, ins, p1, p2, lc = command[:5]

        # Calculate MAC If required
        if self.sec_level & const.SCP_SECLEVEL_C_MAC:
            mac_calculation_input = [cla | 0x04, ins, p1, p2, lc + 8] + command[5:]
            mac = self._calc_mac(mac_calculation_input)

        # Encrypt data if required
        if lc > 5 and self.sec_level & const.SCP_SECLEVEL_C_DECRYPTION:
            padded_data = bytes(self._pad_80(command[5:]))
            cipher = DES3.new(self.session_enc, DES3.MODE_CBC, const.ZERO_IV_8B)
            encrypted_data = list(bytes(cipher.encrypt(padded_data)))

        # Construct secure command based on security level
        if self.sec_level == const.SCP_SECLEVEL_NO_SECURITY_LEVEL:
            secure_command = command
        elif self.sec_level == const.SCP_SECLEVEL_C_MAC:
            secure_command = [cla | 0x04, ins, p1, p2, lc + 8] + command[5:] + mac
        elif (
            self.sec_level == const.SCP_SECLEVEL_C_MAC | const.SCP_SECLEVEL_C_DECRYPTION
        ):
            total_length = len(mac) + len(encrypted_data)
            secure_command = (
                [cla | 0x04, ins, p1, p2, total_length] + encrypted_data + mac
            )

        return self.card_connection.send_apdu(secure_command)

    def _pad_80(self, data_list):
        remainder = len(data_list) % 8
        padding_length = (8 - remainder) or 8
        return data_list + [0x80] + ([0x00] * (padding_length - 1))

    def _calc_mac(self, command):
        padded_command = self._pad_80(command)
        mac_in = bytes(padded_command)

        iv = const.ZERO_IV_8B
        if self.last_mac != None:
            cipher = DES.new(self.session_mac[:8], DES3.MODE_ECB)
            iv = cipher.encrypt(self.last_mac)

        cipher = DES.new(self.session_mac[:8], DES3.MODE_CBC, iv)
        step1 = cipher.encrypt(mac_in)

        cipher = DES.new(self.session_mac[8:16], DES3.MODE_ECB)
        step2 = cipher.decrypt(step1[-8:])

        cipher = DES.new(self.session_mac[:8], DES3.MODE_ECB)
        self.last_mac = cipher.encrypt(step2[-8:])

        return list(self.last_mac)

    def external_authenticate(self, sec_level):

        # GP Specification
        # PADDING_DES = "80 00 00 00 00 00 00 00"
        # host_auth_data = sequence_counter | card_challenge | host_challenge | PADDING_DES

        PADDING_DES = bytes.fromhex("8000000000000000")
        host_auth_data = (
            self.sequence_counter
            + self.card_challenge
            + bytes(self.host_challenge)
            + PADDING_DES
        )

        des3_cipher = DES3.new(self.session_enc, DES3.MODE_CBC, const.ZERO_IV_8B)
        host_cryptogram = (des3_cipher.encrypt(host_auth_data))[-8:]

        # Lc includes an additional 8 bytes reserved for the MAC
        apdu_without_mac = [0x84, 0x82, sec_level, 0x00, (0x08 + 0x08)] + list(
            host_cryptogram
        )
        mac = self._calc_mac(apdu_without_mac)
        external_auth_apdu = apdu_without_mac + mac

        _, sw1, sw2 = self.card_connection.send_apdu(external_auth_apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            self.sec_level = sec_level
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
        # GP Specification
        # derivation_data = DERIVATION_CONST_xxx | sequence_counter |  00 00 00 00 00 00 00 00 00 00 00 00
        # IV = 00 00 00 00 00 00 00 00
        # S_xxx = encrypt(TDES_CBC, K_xxx, IV, derivation_data)

        session_enc_derivation_data = (
            const.GP_DERIVATION_CONST_ENC_SESSION_KEY
            + self.sequence_counter
            + bytes.fromhex("000000000000000000000000")
        )
        session_mac_derivation_data = (
            const.GP_DERIVATION_CONST_MAC_SESSION_KEY
            + self.sequence_counter
            + bytes.fromhex("000000000000000000000000")
        )
        session_dek_derivation_data = (
            const.GP_DERIVATION_CONST_DEK_SESSION_KEY
            + self.sequence_counter
            + bytes.fromhex("000000000000000000000000")
        )

        cipher1 = DES3.new(self.static_enc, DES3.MODE_CBC, const.ZERO_IV_8B)
        cipher2 = DES3.new(self.static_mac, DES3.MODE_CBC, const.ZERO_IV_8B)
        cipher3 = DES3.new(self.static_dek, DES3.MODE_CBC, const.ZERO_IV_8B)

        session_enc_key_parts = cipher1.encrypt(session_enc_derivation_data)
        session_mac_key_parts = cipher2.encrypt(session_mac_derivation_data)
        session_dek_key_parts = cipher3.encrypt(session_dek_derivation_data)

        self.session_enc = session_enc_key_parts + session_enc_key_parts[:8]
        self.session_mac = session_mac_key_parts + session_mac_key_parts[:8]
        self.session_dek = session_dek_key_parts + session_dek_key_parts[:8]

        logger.debug(
            f"Static ENC: {self.static_enc.hex()}, Static MAC: {self.static_mac.hex()}, Static DEK: {self.static_dek.hex()}"
        )
        logger.debug(
            f"Session ENC: {self.session_enc.hex()}, Session MAC: {self.session_mac.hex()}, Session DEK: {self.session_dek.hex()}"
        )

    def initialize_update(self):
        self.reset_session()

        self.host_challenge = list(secrets.token_bytes(8))
        init_update_apdu = [0x80, 0x50, 0x00, 0x00, 0x08] + self.host_challenge

        resp_data, sw1, sw2 = self.card_connection.send_apdu(init_update_apdu)

        if len(resp_data) != 28 or ((sw1, sw2) != (0x90, 0x00)):
            logger.error("Unexpected INIT UPDATE APDU response")
            return False

        self.diversification_data = bytes(resp_data[:10])
        self.key_information = bytes(resp_data[10:12])
        self.sequence_counter = bytes(resp_data[12:14])
        self.card_challenge = bytes(resp_data[14:20])
        self.card_cryptogram = bytes(resp_data[20:])

        self._calc_session_keys()

        # GP Specification
        # PADDING_DES = "80 00 00 00 00 00 00 00"
        # card_auth_data = host_challenge | sequence_counter | card_challenge | PADDING_DES

        PADDING_DES = bytes.fromhex("8000000000000000")

        card_auth_data = (
            bytes(self.host_challenge)
            + self.sequence_counter
            + self.card_challenge
            + PADDING_DES
        )

        des3_cipher = DES3.new(self.session_enc, DES3.MODE_CBC, const.ZERO_IV_8B)
        card_cryptogram = (des3_cipher.encrypt(card_auth_data))[-8:]

        # Let's verify INIT UPDATE response
        if card_cryptogram != self.card_cryptogram:
            logger.error("Wrong ISD Keys! Stop Trying!")
            return False

        return True

    def reset_session(self):
        self.sec_level = 0
        self.session_enc = None
        self.session_mac = None
        self.session_dek = None
        self.last_mac = None
