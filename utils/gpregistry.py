from collections import defaultdict
from typing import List, Dict, Tuple, Optional

COMPONENT_TYPE_PKG = 0
COMPONENT_TYPE_APP = 1


def _read_tag(buf: bytes, i: int) -> Tuple[int, int]:
    """Return (tag_int, new_index)."""
    tag = buf[i]
    i += 1
    if tag & 0x1F == 0x1F:  # multi‑byte tag
        tag = (tag << 8) | buf[i]
        i += 1
    return tag, i


def _read_length(buf: bytes, i: int) -> Tuple[int, int]:
    """Return (length, new_index)."""
    length = buf[i]
    i += 1
    if length & 0x80:  # long‑form length (0x81 or 0x82 expected)
        num_len_bytes = length & 0x7F
        length = int.from_bytes(buf[i : i + num_len_bytes], "big")
        i += num_len_bytes
    return length, i


def _read_value(buf: bytes, i: int, length: int) -> Tuple[bytes, int]:
    """Return (value_bytes, new_index)."""
    return buf[i : i + length], i + length


def parse_tlv(
    buf: bytes, start: int = 0, end: Optional[int] = None
) -> List[Tuple[int, bytes]]:
    """Parse a flat TLV sequence into a list of (tag, value) tuples."""
    end = len(buf) if end is None else end
    out = []
    i = start
    while i < end:
        tag, i = _read_tag(buf, i)
        length, i = _read_length(buf, i)
        value, i = _read_value(buf, i, length)
        out.append((tag, value))
    return out


def parse_e3_sequence(
    buf: List[int], is_packages_info: bool = False
) -> List[Dict[str, object]]:
    """
    Split the top‑level stream into E3 elements, then decode the inner tags
    according to the supplied specification.
    """
    buf = bytes(buf)

    results = []

    i = 0
    while i < len(buf):
        # --- expect E3 container -------------------------------------------
        tag, i_ = _read_tag(buf, i)
        if tag != 0xE3:
            raise ValueError(f"Expected tag 0xE3 at byte {i}, found {tag:02X}")
        length, i_ = _read_length(buf, i_)
        value_start = i_
        value_end = value_start + length
        i = value_end  # advance to next E3

        inner = parse_tlv(buf, value_start, value_end)  # list[(tag,val)]

        elem: Dict[str, object] = defaultdict(list)
        tag_map = {
            0x4F: "aid",
            0x84: "applet_classes_aid",
            0x9F7F: "life_cycle",
            0xC5: "priv",
            0xCF: "selection_param",
            0xC4: "associated_package",
            0xCC: "associated_sd",
            0xCE: "package_version",
        }

        for tag_int, val in inner:
            key = tag_map.get(tag_int)
            if key is None:
                continue  # ignore unexpected tags
            if key == "selection_param":  # repeatable
                elem[key].append(val)
            elif key == "applet_classes_aid":  # repeatable
                elem[key].append(list(val))
            elif key in elem:
                raise ValueError(f"Duplicate single‑occurrence tag {tag_int:02X}")
            elif key in ("aid", "associated_sd", "associated_package"):
                elem[key] = list(val)
            elif key == "life_cycle":
                elem[key] = _get_life_cycle_str(ord(val))
            elif key == "package_version":
                elem[key] = val.hex()
            elif key == "priv":
                elem[key] = _get_priv_str(list(val))
            else:
                elem[key] = val

        # normalise optional non‑repeatable fields that did not appear
        elem.setdefault("package_version", "-")
        elem.setdefault("life_cycle", "-")

        results.append(elem)

    return results


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
        parsed_e3_sequences = parse_e3_sequence(applications_info)

        parsed_applications_info = [
            [item["aid"], item["life_cycle"], item["priv"], item["associated_package"]]
            for item in parsed_e3_sequences
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
        parsed_e3_sequences = parse_e3_sequence(packages_info)
        parsed_packages_info = [
            [
                item["aid"],
                item["life_cycle"],
                item["applet_classes_aid"],
                item["package_version"],
            ]
            for item in parsed_e3_sequences
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
