from collections import defaultdict
from .tlvparser import parse_ber_tlv, find_all_nested_tags

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


def get_parsed_scp_proto_and_i_param(card_recognition_data):
    parsed_crd = parse_ber_tlv(card_recognition_data)

    scp_proto_and_i_param_info = defaultdict(list)
    for element in find_all_nested_tags(parsed_crd, ["66", "73", "64"]):
        application_tag4_oid_tag_list = find_all_nested_tags(element, ["06"])

        for item in application_tag4_oid_tag_list:
            scp_proto, i_param = list(bytes.fromhex(item))[-2:]
            scp_proto_and_i_param_info[f"SCP{scp_proto:02x}"].append(i_param)

    return scp_proto_and_i_param_info
