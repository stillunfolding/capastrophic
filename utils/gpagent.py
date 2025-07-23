import logging
import pathlib
import os
from .const import const
from .gpdata import (
    get_parsed_gp_registry_info,
    get_scp_proto_and_i_param,
    get_parsed_key_info,
)
from zipfile import ZipFile
from .scp02 import SCP02
from .scp03 import SCP03

logger = logging.getLogger("GPAgent")
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t%(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


class GPAgent:
    def __init__(self, card_connection):
        self.card_connection = card_connection
        self.is_mutually_authenticated = False
        self.scp_imp = None

    def send_apdu(self, apdu):
        if self.is_mutually_authenticated and self.scp_imp:
            return self.scp_imp.send_secure_apdu(apdu)
        else:
            return self.card_connection.send_apdu(apdu)

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

    def activeSCPInfoDetection(self, parsed_keys_info):
        resp_data, sw1, sw2 = self.send_apdu(
            [
                0x80,
                0x50,
                0x00,
                0x00,
                0x08,
            ]
            + [
                0x00,
            ]
            * 8
        )

        # Longer challenge is expected (Implicitly it means we have SCP03 in S16 mode)
        if (sw1, sw2) == (0x67, 0x00):
            resp_data, sw1, sw2 = self.send_apdu(
                [
                    0x80,
                    0x50,
                    0x00,
                    0x00,
                    0x10,
                ]
                + [
                    0x00,
                ]
                * 16
            )

        # Active Fallback failed!
        if (sw1, sw2) != (0x90, 0x00):
            return const.SCP_PROTO_NONE, None, None

        key_version, scp_proto = resp_data[10:12]

        if scp_proto == 0x02:
            # We make an assumption for the implementation param "i"!
            return const.SCP_PROTO_SCP02, 0x15, const.KEY_LENGTH_2K3DES

        if scp_proto == 0x03:
            for key in parsed_keys_info:
                if key["key_id"] == "01" and key["key_version"] == key_version:
                    return (
                        const.SCP_PROTO_SCP03,
                        resp_data[12],
                        key["components"].get("length"),
                    )

        return const.SCP_PROTO_NONE, None, None

    def determineSCPAndKeyLength(self):
        CRD_TAG = [0x00, 0x66]
        KEY_INFO_TAG = [0x00, 0xE0]

        card_recognition_data, _, _ = self.card_connection.send_apdu(
            [0x80, 0xCA, *CRD_TAG, 0x00]
        )
        scp_proto_i_param = get_scp_proto_and_i_param(card_recognition_data)

        keys_info, _, _ = self.card_connection.send_apdu(
            [0x80, 0xCA, *KEY_INFO_TAG, 0x00]
        )

        parsed_keys_info = get_parsed_key_info(keys_info)

        scp02_i_param = scp_proto_i_param.get(const.SCP_PROTO_SCP02, None)
        scp03_i_param = scp_proto_i_param.get(const.SCP_PROTO_SCP03, None)

        if scp02_i_param and not scp03_i_param:
            return const.SCP_PROTO_SCP02, scp02_i_param, const.KEY_LENGTH_2K3DES

        elif scp03_i_param and not scp02_i_param:
            # Assumption: The first AES key with KeyID = 0x01 in the Key Info Data element
            # is assumed to be the key used for Secure Channel Protocol (SCP) when P1 = 0x00
            # in the INIT UPDATE command. (TODO: Verify and clarify this assumption.)
            for key in parsed_keys_info:
                if key["key_id"] != "01":
                    continue

                for component in key.get("components", []):
                    if component.get("type") == "AES":
                        return (
                            const.SCP_PROTO_SCP03,
                            scp03_i_param,
                            component.get("length"),
                        )

        elif scp02_i_param and scp03_i_param:  # Both are supported
            # Assumption: The first AES/DES key with KeyID = 0x01 in the Key Info Data element
            # is assumed to be the key used for Secure Channel Protocol (SCP) when P1 = 0x00
            # in the INIT UPDATE command. (TODO: Verify and clarify this assumption.)
            for key in parsed_keys_info:
                if key["key_id"] != "01":
                    continue

                for component in key.get("components", []):
                    if component.get("type") == "AES":
                        return (
                            const.SCP_PROTO_SCP03,
                            scp03_i_param,
                            component.get("length"),
                        )
                    if component.get("type") == "DES":
                        return (
                            const.SCP_PROTO_SCP02,
                            scp02_i_param,
                            component.get("length"),
                        )

            # Fallback! check all other keys if KeyID = 0x01 didn't provide an expected outcome (AES/DES)
            for key in parsed_keys_info:
                if key["key_id"] != "01":
                    continue

                for component in key.get("components", []):
                    if component.get("type") == "AES":
                        return (
                            const.SCP_PROTO_SCP03,
                            scp03_i_param,
                            component.get("length"),
                        )
                    if component.get("type") == "DES":
                        return (
                            const.SCP_PROTO_SCP02,
                            scp02_i_param,
                            component.get("length"),
                        )

        logger.debug(
            "Active Fallback: SCP info detection by sending a redundant INIT-UPDATE command!"
        )
        return self.activeSCPInfoDetection(parsed_keys_info)

    def mutual_auth(
        self,
        sec_level=const.SCP_SECLEVEL_NO_SECURITY_LEVEL,
        static_enc=const.KEY_40_4F_16B,
        static_mac=const.KEY_40_4F_16B,
        static_dek=const.KEY_40_4F_16B,
        sd_aid=[],
    ):
        self.is_mutually_authenticated = False

        if not self.select_isd(sd_aid):
            return False

        protocol, i_param, keylength = self.determineSCPAndKeyLength()

        match protocol:
            case const.SCP_PROTO_SCP02:
                if i_param in (0x15, 0x55):
                    self.scp_imp = SCP02(
                        self.card_connection, static_enc, static_mac, static_dek
                    )
                else:
                    logger.error(f"SCP Protocol not implemented!")
                    return False

            case const.SCP_PROTO_SCP03:
                self.scp_imp = SCP03(
                    self.card_connection,
                    static_enc
                    * (
                        keylength // len(static_mac)
                    ),  # if 4041...4F used instead of full 32B (4041...4F4041...4F)
                    static_mac
                    * (
                        keylength // len(static_mac)
                    ),  # if 4041...4F used instead of full 32B (4041...4F4041...4F)
                    static_dek
                    * (
                        keylength // len(static_mac)
                    ),  # if 4041...4F used instead of full 32B (4041...4F4041...4F)
                    i_param,
                )
            case _:
                logger.error(f"Implemented SCP Protocol is not supported!")
                return False

        if not self.scp_imp.initialize_update():
            return False

        if not self.scp_imp.external_authenticate(sec_level):
            return False

        self.is_mutually_authenticated = True
        return True

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
            logger.error(f"Load failed; {cap_file_path} not found!")
            return False

        if not self.is_mutually_authenticated:
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

        _, sw1, sw2 = self.scp_imp.send_secure_apdu(install_for_load_apdu)
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

            _, sw1, sw2 = self.scp_imp.send_secure_apdu(load_apdu)

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
        priviledges=[0x00],
        install_params=[],
    ):

        if not self.is_mutually_authenticated:
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

        _, sw1, sw2 = self.scp_imp.send_secure_apdu(install_apdu)
        if (sw1, sw2) != (0x90, 0x00):
            logger.error(
                f"Failed to install appelt. INSTALL [for install and make selectable] returns {sw1:02X}{sw2:02X}"
            )
            return False

        return True

    def list_content(self, deprecated_data_structure=False):

        if not self.is_mutually_authenticated:
            logger.error("List Content failed; Mutual Auth is required!")
            return [], []

        # data type constains
        P1_ISD_INFO = 0x80
        P1_APPLICATIONS_INFO = 0x40
        P1_PACKAGES_INFO = 0x10

        # retrieval type constants
        data_struct = 0 if deprecated_data_structure else 2
        P2_GET_ALL = 0x00 | data_struct
        P2_GET_NEXT = 0x01 | data_struct

        # ISD
        ISD_status_info, sw1, sw2 = self.scp_imp.send_secure_apdu(
            [0x80, 0xF2, P1_ISD_INFO, P2_GET_ALL, 0x02, 0x4F, 0x00]
        )
        while (sw1, sw2) == (0x63, 0x10):
            get_status_isd_apdu = [
                0x80,
                0xF2,
                P1_ISD_INFO,
                P2_GET_NEXT,
                0x02,
                0x4F,
                0x00,
            ]
            next_info, sw1, sw2 = self.scp_imp.send_secure_apdu(get_status_isd_apdu)
            ISD_status_info += next_info

        # Applets and SSDs
        applications_status_resp_data, sw1, sw2 = self.scp_imp.send_secure_apdu(
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
            next_info, sw1, sw2 = self.scp_imp.send_secure_apdu(get_status_applets_apdu)
            applications_status_resp_data += next_info

        # Packages
        packages_status_resp_data, sw1, sw2 = self.scp_imp.send_secure_apdu(
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
            next_info, sw1, sw2 = self.scp_imp.send_secure_apdu(
                get_status_packages_apdu
            )
            packages_status_resp_data += next_info

        applications_info, packages_info = get_parsed_gp_registry_info(
            ISD_status_info + applications_status_resp_data, packages_status_resp_data
        )
        return applications_info, packages_info

    def delete_content(self, aid):

        if not self.is_mutually_authenticated:
            logger.error("Load failed; Mutual Auth is required!")
            return False

        delete_apdu = [0x80, 0xE4, 0x00, 0x80, len(aid) + 2] + [0x4F, len(aid)] + aid

        _, sw1, sw2 = self.scp_imp.send_secure_apdu(delete_apdu)
        if (sw1, sw2) != (0x90, 0x00):
            logger.error(f"Failed to delete {bytes(aid).hex()}: {sw1:02X}{sw2:02X}")
            return False

        return True
