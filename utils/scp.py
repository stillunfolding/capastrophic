import logging
import pathlib
import os
import secrets
from Crypto.Cipher import DES3, DES
from .const import const
from .gpregistry import get_parsed_gp_registry_info
from zipfile import ZipFile


logger = logging.getLogger("SCP")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t%(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


class SCP:
    def __init__(self, card_connection):
        self.card_connection = card_connection
        self.mutual_authenticated = False
        self.sec_level = 0

        self.static_enc = None
        self.static_mac = None
        self.static_dek = None

        self.session_enc = None
        self.session_mac = None
        self.session_dek = None

        self.last_mac = None

    def send_secure_apdu(self, command):

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
        self.host_challenge = list(secrets.token_bytes(8))
        init_update_apdu = const.INIT_UPDATE_APDU_CMD_HEADER + self.host_challenge

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

    def select_isd(self, sd_aid):

        if sd_aid:
            select_apdu = [0x00, 0xA4, 0x04, 0x00] + [len(sd_aid)] + sd_aid

        else:
            select_apdu = [0x00, 0xA4, 0x04, 0x00, 0x00]
            resp_data, sw1, sw2 = self.card_connection.send_apdu(select_apdu)

            if (sw1, sw2) != (0x90, 0x00):
                logger.error(
                    "SD AID extraction from FCI was failed; possibly partial Select APDU is not supported?"
                )
                return False

            fci_tag_index = resp_data.index(0x6F)
            aid_len = resp_data[fci_tag_index + 3]
            aid_start_index = fci_tag_index + 4
            aid_end_index = aid_start_index + aid_len
            sd_aid = resp_data[aid_start_index:aid_end_index]
            select_apdu = [0x00, 0xA4, 0x04, 0x00] + [aid_len] + sd_aid

        _, sw1, sw2 = self.card_connection.send_apdu(select_apdu)

        if (sw1, sw2) != (0x90, 0x00):
            logger.error(
                "SD AID extraction from FCI was failed; possibly partial Select APDU is not supported?"
            )
            return False

        self.sd_aid = sd_aid
        return True

    def _clean_keys(self):
        self.static_enc = None
        self.static_mac = None
        self.static_dek = None
        self.session_enc = None
        self.session_mac = None
        self.session_dek = None
        self.last_mac = None

    def reset_session(self):
        self.sec_level = 0
        self.mutual_authenticated = False
        self._clean_keys()

    def mutual_auth(
        self,
        sec_level=const.SCP_SECLEVEL_NO_SECURITY_LEVEL,
        static_enc=const.KEY_40_4F_16B,
        static_mac=const.KEY_40_4F_16B,
        static_dek=const.KEY_40_4F_16B,
        sd_aid=[],
    ):

        self.sec_level = sec_level
        self.mutual_authenticated = False
        self._clean_keys()

        if not self.select_isd(sd_aid):
            return False

        self.static_enc = static_enc
        self.static_mac = static_mac
        self.static_dek = static_dek

        if not self.initialize_update():
            return False

        if self.external_authenticate(sec_level):
            self.mutual_authenticated = True
            return True
        else:
            return False

    def _get_reordered_components(
        self, components, components_order, apply_order_to_head
    ):
        # "startswith" ensures both compact and extended component names are matched.
        NORMAL_INSTALL_ORDER = [
            "header",  # 1
            "directory",  # 2
            "import",  # 4
            "applet",  # 3
            "class",  # 6
            "method",  # 7
            "staticfield",  # 8
            "export",  # 10
            "constantpool",  # 5
            "reflocation",  # 9
            "staticresources",  # 13
            "descriptor",  # 11
        ]

        # Let's get rid of debug components, as they are not loaded on the card
        components.pop("debug.cap", None)
        components.pop("debug.capx", None)

        if not components_order:
            ordering_reference = NORMAL_INSTALL_ORDER
        else:
            # first normalize the names in the requested list
            requested_order = list()
            for item in components_order:
                name_part = os.path.splitext(item)[0].lower()
                if name_part not in NORMAL_INSTALL_ORDER:
                    logger.warning(
                        f"Unexpected component name in the requested order: {name_part}"
                    )
                requested_order.append(name_part)

            # then create ordering_reference
            if apply_order_to_head:
                ordering_reference = list(
                    dict.fromkeys(requested_order + NORMAL_INSTALL_ORDER)
                )
            else:
                # Custom components not in the lists (if any) are appended at the end, automatically
                ordering_reference = list(
                    dict.fromkeys(requested_order[::-1] + NORMAL_INSTALL_ORDER[::-1])
                )[::-1]

        return [
            *(
                components.get(
                    f"{component_name}.cap", components.get(f"{component_name}.capx")
                )
                for component_name in ordering_reference
                if any(name.startswith(component_name) for name in components.keys())
            ),
            *(
                component_data
                for component_name, component_data in components.items()
                if all(
                    not component_name.startswith(name) for name in ordering_reference
                )
            ),
        ]

    def _get_cap_components(self, cap_file_path, components_order, apply_order_to_head):
        cap_archive = ZipFile(cap_file_path)

        all_paths = cap_archive.namelist()

        components = {
            os.path.basename(path).lower(): cap_archive.read(path)
            for path in all_paths
            if path.lower().endswith((".cap", ".capx"))
        }

        return self._get_reordered_components(
            components, components_order, apply_order_to_head
        )

    def _get_encoded_length(self, length):

        # Short form: 0–127
        if length <= 0x7F:
            return bytes([length])

        # Long form: first byte 0x80 | num_length_bytes
        needed_bytes = (length.bit_length() + 7) // 8
        prefix = 0x80 | needed_bytes

        return bytes([prefix]) + length.to_bytes(needed_bytes, byteorder="big")

    def _get_load_chunks(self, load_file_data_block, chunk_sizes, apply_sizes_to_head):
        DEFAULT_CHUNCK_SIZE = 100  # in bytes
        if not chunk_sizes:
            return [
                load_file_data_block[i : i + DEFAULT_CHUNCK_SIZE]
                for i in range(0, len(load_file_data_block), DEFAULT_CHUNCK_SIZE)
            ]

        # If chunk_sizes defines the last N chunk lengths (from the end),
        # reverse data and sizes, split, then reverse chunks (and the bytes) back.
        if not apply_sizes_to_head:
            chunk_sizes.reverse()
            load_file_data_block = load_file_data_block[::-1]

        remaining_bytes = len(load_file_data_block)
        offset = 0
        chunks = list()

        while chunk_sizes:
            this_chunk_size = chunk_sizes.pop(0)
            if this_chunk_size > remaining_bytes:
                break

            chunks.append(load_file_data_block[offset : offset + this_chunk_size])
            offset += this_chunk_size
            remaining_bytes -= this_chunk_size

        if remaining_bytes:
            chunks += [
                load_file_data_block[i : i + DEFAULT_CHUNCK_SIZE]
                for i in range(
                    len(load_file_data_block) - remaining_bytes,
                    len(load_file_data_block),
                    DEFAULT_CHUNCK_SIZE,
                )
            ]
        if not apply_sizes_to_head:
            return [chunk[::-1] for chunk in chunks[::-1]]

        return chunks

    def load_cap(
        self,
        cap_file_path,
        cap_aid,  # package AID in compact format
        sd_aid=[],
        load_params=[],
        components_order=[],
        apply_order_to_head=True,
        chunk_sizes=[],
        apply_sizes_to_head=True,
    ):
        if not pathlib.Path(cap_file_path).exists():
            logger.error(f"Load faile; {cap_file_path} not found!")
            return False

        if not self.mutual_authenticated:
            logger.error("Load failed; Mutual Auth is required!")
            return False

        # INSTALL [for load] Command
        # Data: Len(PKG/CAP AID) - PKG/CAP AID - Len(SD AID) - [SD AID] - Len(LFDBH) - [LFDBH] -\
        #       Len(Load Params) - [Load Params] - Len(Load Token) - [Load Token]

        # We assume: No LFDBH, No Load Token
        lfdbh = []
        token = []
        lc = (
            1
            + len(cap_aid)
            + 1
            + len(sd_aid)
            + 1
            + len(lfdbh)
            + 1
            + len(load_params)
            + 1
            + len(token)
        )

        install_for_load_apdu = (
            [0x80, 0xE6, 0x02, 0x00, lc]
            + [len(cap_aid)]
            + cap_aid
            + [len(sd_aid)]
            + sd_aid
            + [len(lfdbh)]  # Len(LFDBH)
            + lfdbh
            + [len(load_params)]
            + load_params
            + [len(token)]  # Len(LOAD Token)
            + token
        )

        _, sw1, sw2 = self.send_secure_apdu(install_for_load_apdu)
        if not (sw1 == 0x90 and sw2 == 0x00):
            logger.error(f"Load failed; INSTALL [for LOAD] returns {sw1:02X}{sw2:02X}")
            return False

        # Get CAP components in default or requested order
        components = self._get_cap_components(
            cap_file_path, components_order, apply_order_to_head
        )

        load_file_data = b"".join(components)
        load_file_data_block = (
            b"\xc4" + self._get_encoded_length(len(load_file_data)) + load_file_data
        )

        chunks = self._get_load_chunks(
            load_file_data_block, chunk_sizes, apply_sizes_to_head
        )

        for chunk_id, chunk in enumerate(chunks):
            # Set P1: 0x80 if this is the last chunk, 0x00 otherwise
            is_last_chunk = chunk_id == len(chunks) - 1
            p1 = 0x80 if is_last_chunk else 0x00

            load_apdu = [0x80, 0xE8, p1, chunk_id, len(chunk)] + list(chunk)

            _, sw1, sw2 = self.send_secure_apdu(load_apdu)

            if (sw1, sw2) != (0x90, 0x00):
                logger.error(
                    f"Failed to install appelt. LOAD returns {sw1:02X}{sw2:02X}"
                )
                return False

        return True

    def install_applet(
        self,
        cap_aid,  # package AID in compact format
        class_aid,  # applet AID within a package
        instance_aid,  # to be instanciated applet
        priviledges=[],
        install_params=[],
    ):

        if not self.mutual_authenticated:
            logger.error("Load failed; Mutual Auth is required!")
            return False

        # INSTALL [for install and make selectbale] Command
        # Data: Len(PKC/CAP AID) - PKG/CAP AID - Len(Applet Class AID) - Applet Class AID - Len(Instance AID) - Instance AID -\
        #       Len(Privs) - Privs - Len(Install Params) - Install Params - Len(Token) - [Install Token]

        # We assume: No Load Token
        token = []
        lc = (
            1
            + len(cap_aid)
            + 1
            + len(class_aid)
            + 1
            + len(instance_aid)
            + 1
            + len(priviledges)
            + 1
            + len(install_params)
            + 1
            + len(token)
        )

        install_apdu = (
            [0x80, 0xE6, 0x0C, 0x00, lc]
            + [len(cap_aid)]
            + cap_aid
            + [len(class_aid)]
            + class_aid
            + [len(instance_aid)]
            + instance_aid
            + [len(priviledges)]
            + priviledges
            + [len(install_params)]
            + install_params
            + [len(token)]
            + token
        )

        _, sw1, sw2 = self.send_secure_apdu(install_apdu)
        if (sw1, sw2) != (0x90, 0x00):
            logger.error(
                f"Failed to install appelt. INSTALL [for install and make selectable] returns {sw1:02X}{sw2:02X}"
            )
            return False

        return True

    def list_content(self, deprecated_data_structure=False):

        if not self.mutual_authenticated:
            logger.error("List Content failed; Mutual Auth is required!")
            return None

        # data type constains
        P1_APPLICATIONS_INFO = 0x40
        P1_PACKAGES_INFO = 0x10

        # retrieval type constants
        data_struct = 0 if deprecated_data_structure else 2
        P2_GET_ALL = 0x00 | data_struct
        P2_GET_NEXT = 0x01 | data_struct

        applications_info, sw1, sw2 = self.send_secure_apdu(
            [0x80, 0xF2, P1_APPLICATIONS_INFO, P2_GET_ALL, 0x02, 0x4F, 0x00]
        )
        while (sw1, sw2) == (0x63, 0x10):
            get_status_applets_apdu = [
                0x80,
                0xF2,
                P1_APPLICATIONS_INFO,
                P2_GET_NEXT,
                0x02,
                0x4F,
                0x00,
            ]
            next_info, sw1, sw2 = self.send_secure_apdu(get_status_applets_apdu)
            applications_info += next_info

        packages_info, sw1, sw2 = self.send_secure_apdu(
            [0x80, 0xF2, P1_PACKAGES_INFO, P2_GET_ALL, 0x02, 0x4F, 0x00]
        )
        while (sw1, sw2) == (0x63, 0x10):
            get_status_packages_apdu = [
                0x80,
                0xF2,
                P1_PACKAGES_INFO,
                P2_GET_NEXT,
                0x02,
                0x4F,
                0x00,
            ]
            next_info, sw1, sw2 = self.send_secure_apdu(get_status_packages_apdu)
            packages_info += next_info

        applications_info, packages_info = get_parsed_gp_registry_info(
            applications_info, packages_info
        )
        return applications_info, packages_info

    def delete_content(self, aid):

        if not self.mutual_authenticated:
            logger.error("Load failed; Mutual Auth is required!")
            return False

        delete_apdu = [0x80, 0xE4, 0x00, 0x80, len(aid) + 2] + [0x4F, len(aid)] + aid

        _, sw1, sw2 = self.send_secure_apdu(delete_apdu)
        if (sw1, sw2) != (0x90, 0x00):
            logger.error(f"Failed to delete {bytes(aid).hex()}: {sw1:02X}{sw2:02X}")
            return False

        return True
