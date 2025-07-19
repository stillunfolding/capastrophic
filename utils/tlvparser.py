import sys
import json


def parse_tag(data, index):
    tag_bytes = [data[index]]
    index += 1
    if tag_bytes[0] & 0x1F == 0x1F:
        # Multi-byte tag
        while data[index] & 0x80:
            tag_bytes.append(data[index])
            index += 1
        tag_bytes.append(data[index])
        index += 1
    return bytes(tag_bytes), index


def parse_length(data, index):
    length_byte = data[index]
    index += 1
    if length_byte < 0x80:
        return length_byte, index
    num_bytes = length_byte & 0x7F
    length = int.from_bytes(data[index : index + num_bytes], byteorder="big")
    index += num_bytes
    return length, index


def parse_ber_tlv(data, depth=0):
    index = 0
    result = []

    data = bytes(data)

    while index < len(data):
        tag, index = parse_tag(data, index)
        length, index = parse_length(data, index)
        value = data[index : index + length]
        index += length

        is_constructed = tag[0] & 0x20 == 0x20

        children = []
        if is_constructed:
            children = parse_ber_tlv(value, depth + 1)

        result.append(
            {
                "tag": tag.hex().upper(),
                "length": length,
                "value": children if is_constructed else value.hex().upper(),
            }
        )

    return result


def find_nested_tag(tlv_list, tag_sequence):
    """
    Recursively navigate a sequence of nested TLVs to find the value of the innermost tag.

    :param tlv_list: Parsed TLV list (from parse_ber_tlv)
    :param tag_sequence: List of tag strings to follow (e.g., ['66', '73', '06'])
    :return: Value (hex string or nested structure) of the final tag, or None if not found
    """
    if not tag_sequence:
        return None

    target_tag = tag_sequence[0].upper()

    for item in tlv_list:
        if item["tag"] == target_tag:
            if len(tag_sequence) == 1:
                return item["value"]  # Found the target
            if isinstance(item["value"], list):
                return find_nested_tag(item["value"], tag_sequence[1:])
    return None


def find_all_nested_tags(tlv_list, tag_sequence):
    """
    Recursively find all values that match a tag sequence (including repeated tags at the same level).

    :param tlv_list: Parsed TLV list (from parse_ber_tlv)
    :param tag_sequence: List of tag strings to follow (e.g., ['66', '73', '06'])
    :return: List of matching values
    """
    if not tag_sequence:
        return []

    target_tag = tag_sequence[0].upper()
    results = []

    for item in tlv_list:
        if item["tag"] == target_tag:
            if len(tag_sequence) == 1:
                # Final target level — collect value
                results.append(item["value"])
            elif isinstance(item["value"], list):
                # Recurse deeper
                results.extend(find_all_nested_tags(item["value"], tag_sequence[1:]))

    return results


if __name__ == "__main__":
    print("Parsing BER-TLV...")
    parsed_tlv = parse_ber_tlv(bytes.fromhex(sys.argv[1].replace(" ", "")))
    print(json.dumps(parsed_tlv, indent=2))
