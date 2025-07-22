from collections import defaultdict
from .tlvparser import parse_ber_tlv, find_all_nested_tags
from io import BytesIO

COMPONENT_TYPE_PKG = 0
COMPONENT_TYPE_APP = 1


def _get_life_cycle_str(life_cycle_int, component_type):
    if component_type == COMPONENT_TYPE_PKG:
        return "LOADED" if life_cycle_int == 0x01 else "UNKNOWN"

    elif (
        component_type == COMPONENT_TYPE_APP
    ):  # Merged with SD Specific one (Personalized: 0x0F)
        if life_cycle_int == 0x03:
            return "INSTALLED"
        elif life_cycle_int == 0x07:
            return "SELECTABLE"
        elif life_cycle_int == 0x0F:
            return "PERSONALIZED"
        elif life_cycle_int & 0x83 == 0x03:
            return "APP-SPECIFIC"
        elif life_cycle_int & 0x83 == 0x83:
            return "LOCKED"
        else:
            return "UNKNOWN"


def _get_priv_str(priv_list):
    """Convert a list of privilege bytes into a human-readable string."""
    BYTE_MAPS = [
        {
            0x80: "Security Domain",
            0xC0: "DAP Verification",
            0xA0: "Delegated Management",
            0x10: "Card Lock",
            0x08: "Card Terminate",
            0x04: "Card Reset",
            0x02: "CVM Management",
            0xC1: "Mandated DAP Verification",
        },
        {
            0x80: "Trusted Path",
            0x40: "Authorized Management",
            0x20: "Token Management",
            0x10: "Global Delete",
            0x08: "Global Lock",
            0x04: "Global Registry",
            0x02: "Final Application",
            0x01: "Global Service",
        },
        {
            0x80: "Receipt Generation",
            0x40: "CFLDB",
            0x20: "Contactless Activation",
            0x10: "Contactless Self-Activation",
        },
    ]

    privileges = []

    for index, byte_map in enumerate(BYTE_MAPS):
        if index < len(priv_list):
            byte_value = priv_list[index]
            privileges.extend(
                name
                for bitmask, name in byte_map.items()
                if byte_value & bitmask == bitmask
            )

    return ", ".join(privileges) if privileges else "-"


def get_parsed_gp_registry_info(applications_info, packages_info):
    GP_REGISTRY_RELATED_DATA_TAG = 0xE3

    if applications_info[0] == GP_REGISTRY_RELATED_DATA_TAG:
        parsed_tlv = parse_ber_tlv(applications_info)
        e3_elements = find_all_nested_tags(parsed_tlv, ["E3"])

        applications = list()
        for element in e3_elements:

            app_info = defaultdict(list)
            for tlv in element:
                tag = tlv["tag"]
                value = tlv["value"]

                if tag == "4F":
                    app_info["aid"] = list(bytes.fromhex(value))
                elif tag == "9F70":
                    app_info["life_cycle"] = _get_life_cycle_str(
                        int(value, 16), COMPONENT_TYPE_APP
                    )
                elif tag == "C5":
                    app_info["priv"] = _get_priv_str(list(bytes.fromhex(value)))
                elif tag == "C4":
                    app_info["associated_package"] = list(bytes.fromhex(value))

            applications.append(app_info)

        parsed_applications_info = [
            [
                app["aid"],
                app.get("life_cycle", "-"),
                app.get("priv", "-"),
                app.get("associated_package", []),
            ]
            for app in applications
        ]

    else:  # The deprecated data structure, where P2.B2 is 0 in the GET STATUS APDU command.
        parsed_applications_info = list()
        while len(applications_info):
            aid_len = applications_info.pop(0)
            aid = [applications_info.pop(0) for _ in range(aid_len)]
            life_cycle = _get_life_cycle_str(
                applications_info.pop(0), COMPONENT_TYPE_APP
            )
            privileges = _get_priv_str([applications_info.pop(0)])
            associated_pkg = []  # to align with E3 sequence return format
            parsed_applications_info.append(
                [aid, life_cycle, privileges, associated_pkg]
            )

    if packages_info[0] == GP_REGISTRY_RELATED_DATA_TAG:
        parsed_tlv = parse_ber_tlv(packages_info)
        e3_elements = find_all_nested_tags(parsed_tlv, ["E3"])

        packages = list()
        for element in e3_elements:
            pkg_info = defaultdict(list)
            for tlv in element:
                tag = tlv["tag"]
                value = tlv["value"]
                if tag == "4F":
                    pkg_info["aid"] = list(bytes.fromhex(value))
                if tag == "9F70":
                    pkg_info["life_cycle"] = _get_life_cycle_str(
                        int(value, 16), COMPONENT_TYPE_PKG
                    )
                if tag == "84":
                    pkg_info["applet_classes_aid"].append(list(bytes.fromhex(value)))
                if tag == "CE":
                    pkg_info["package_version"] = list(bytes.fromhex(value))

            packages.append(pkg_info)

        parsed_packages_info = [
            [
                pkg["aid"],
                pkg.get("life_cycle", "-"),
                pkg.get("applet_classes_aid", []),
                pkg.get("package_version", "-"),
            ]
            for pkg in packages
        ]

    else:  # The deprecated structure, where P2.B2 is 0 in the GET STATUS APDU command.
        parsed_packages_info = list()
        while len(packages_info):
            package_aid_len = packages_info.pop(0)
            aid = [packages_info.pop(0) for _ in range(package_aid_len)]
            life_cycle = _get_life_cycle_str(packages_info.pop(0), COMPONENT_TYPE_PKG)
            _ = packages_info.pop(0)  # privileges (deprecated)
            number_of_applet_classes = packages_info.pop(0)
            applet_classes = list()
            for _ in range(number_of_applet_classes):
                class_aid_len = packages_info.pop(0)
                class_aid = [packages_info.pop(0) for _ in range(class_aid_len)]
                applet_classes.append(class_aid)
            version = "-"  # to align with E3 sequence return format

            parsed_packages_info.append([aid, life_cycle, applet_classes, version])

    return (parsed_applications_info, parsed_packages_info)


def get_scp_proto_and_i_param(card_recognition_data):
    parsed_crd = parse_ber_tlv(card_recognition_data)

    # Assumption: For each SCP protocol, it is assumed that the card supports only a single implementation.
    # For example, I do not expect SCP02 to be present with both i=15 and i=55 simultaneously.
    # This assumption should be reviewed and validated further. (#ToDo)
    scp_proto_and_i_param = dict()
    for element in find_all_nested_tags(parsed_crd, ["66", "73", "64"]):
        application_tag4_oid_tag_list = find_all_nested_tags(element, ["06"])

        for item in application_tag4_oid_tag_list:
            scp_proto, i_param = list(bytes.fromhex(item))[-2:]
            scp_proto_and_i_param[f"SCP{scp_proto:02x}"] = i_param

    return scp_proto_and_i_param


def _get_key_type_str(key_type):
    KEY_TYPE_MAP = {
        "80": "DES",
        "85": "TLS Pre-Shared",
        "88": "AES",
        "90": "HMAC-SHA1",
        "91": "HMAC-SHA1-160",
        "A0": "RSA Public - exponent e component (clear text)",
        "A1": "RSA Public - modulus N component (clear text)",
        "A2": "RSA Private - modulus N component",
        "A3": "RSA Private - exponent d component",
        "A4": "RSA Private CRT - P",
        "A5": "RSA Private CRT - Q",
        "A6": "RSA Private CRT - PQ: q-1 mod p",
        "A7": "RSA Private CRT - DP1: d mod (p-1)",
        "A8": "RSA Private CRT - DQ1: d mod (q-1)",
        "B0": "ECC public",
        "B1": "ECC private",
        "B2": "ECC field parameter P (field specification)",
        "B3": "ECC field parameter A (first coefficient)",
        "B4": "ECC field parameter B (second coefficient)",
        "B5": "ECC field parameter G (generator)",
        "B6": "ECC field parameter N (order of generator)",
        "B7": "ECC field parameter k (cofactor of order of generator)",
        "F0": "ECC key parameters reference",
    }
    return KEY_TYPE_MAP.get(key_type, f"Unknown/{key_type}")


def get_parsed_key_info(key_info_hex: str):
    """
    Parses key information encoded in BER-TLV format, extracting key ID, version,
    key components, usage rights, and access conditions.

    Args:
        key_info_list : A list containing the BER-TLV encoded key information.

    Returns:
        list[dict]: A list of parsed key dictionaries with keys:
                    - key_id
                    - key_version
                    - components (list of dicts with type and length)
                    - usage (hex str, conditional)
                    - access (hex str, conditional)
    """
    parsed_tlv = parse_ber_tlv(key_info_hex)
    key_entries = find_all_nested_tags(parsed_tlv, ["E0", "C0"])

    parsed_keys = []

    for entry_hex in key_entries:
        entry_bytes = bytes.fromhex(entry_hex)
        byte_stream = BytesIO(entry_bytes)

        key_id = byte_stream.read(1).hex()
        key_version = byte_stream.read(1).hex()

        # The third byte defines the format: 0xFF indicates extended format
        is_extended_format = entry_bytes[2] == 0xFF

        components = []

        while byte_stream.tell() < len(entry_bytes):
            if is_extended_format:
                component_type = byte_stream.read(2)
                if component_type[0] != 0xFF:
                    byte_stream.seek(byte_stream.tell() - 2)
                    break
                component_length = int.from_bytes(byte_stream.read(2), "big")
            else:
                component_type = byte_stream.read(1)
                component_length = int.from_bytes(byte_stream.read(1), "big")

            components.append(
                {
                    "type": _get_key_type_str(component_type.hex().upper()),
                    "length": component_length,
                }
            )

            key_type = byte_stream.read(1).hex()
            if key_type.upper() == "FF":
                key_type += byte_stream.read(1).hex()

            if is_extended_format:
                key_data_length = int.from_bytes(byte_stream.read(2), "big")
            else:
                key_data_length = int.from_bytes(byte_stream.read(1), "big")

            byte_stream.read(key_data_length)  # Skip over actual key data

        key_usage = key_access = None
        if is_extended_format and byte_stream.tell() < len(entry_bytes):
            usage_length = int.from_bytes(byte_stream.read(1), "big")
            key_usage = byte_stream.read(usage_length).hex()

            access_length = int.from_bytes(byte_stream.read(1), "big")
            key_access = byte_stream.read(access_length).hex()

        parsed_keys.append(
            {
                "key_id": key_id,
                "key_version": key_version,
                "components": components,
                "usage": key_usage,
                "access": key_access,
            }
        )

    return parsed_keys
