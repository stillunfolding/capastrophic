#!/usr/bin/python3

import argparse
from datetime import datetime
import os
import sys
import json
import logging

logger = logging.getLogger("Installer")
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t%(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


# bytes to int
def b2i(bytes, endian="big"):
    return int.from_bytes(bytes, endian)


class EXP2JSON:
    """
    ExportFile Structure:
    =====================

    | u4  magic
    | u1  minor_version
    | u1  major_version
    |
    | u2  constant_pool_count
    | cp_info constant_pool[constant_pool_count]    ----> no ordering constraint
    |
    | u2  this_package                  ----> A valid index into the constant_pool; must be of type "CONSTANT_Package_info"
    |
    | u1  referenced_package_count      ----> (since Export File format 2.3)
    | u2  referenced_packages[referenced_package_count]
    |                                    ----> (since Export File format 2.3)
    |                                    ----> Indexes into the constant_pool; must be of type "CONSTANT_Package_info"
    |
    | u1  export_class_count
    | class_info classes[export_class_count]
    |                                    ----> Describes publicly accessible classes/interfaces declared in this package
                                                + In Java Card, following items are externally visible:
                                                    1) "public" classes (and interfaces),
                                                    2) "public" or "protected" methods,
                                                    3) "public" or "protected" fields
                                                Hence, to make on-device reference-resolution possible for the items other
                                                packages have reference to), following six kinds of items in the packages
                                                require external identification (using tokes):
                                                    1) classes (and interfaces)
                                                    2) static methods
                                                    3) virtual methods
                                                    4) interface methods
                                                    5) static fields
                                                    6) instance fields



        Constant Pool Entries:
        ======================

        | cp_info {
        |   u1 tag                          ----> 1: UTF8, 3: Integer, 7: ClassRef, 13: Package
        |   u1 info[]
        | }


            | CONSTANT_Utf8_info {
            |   u1 tag
            |   u2 length
            |   u1 bytes[length]                ----> 0x00 and [0xf0-0xff] are unexpected per JCVM Spec
            | }

            | CONSTANT_Integer_info {
            |   u1 tag
            |   u4 bytes
            | }

            | CONSTANT_Classref_info {          ----> Represents a class or an interface
            |   u1 tag
            |   u2 name_index                   ----> CONSTANT_Utf8_info entry in constant pool
            | }

            | CONSTANT_Package_info {
            |   u1 tag
            |   u1 flags
            |   u2 name_index                   ----> Valid index into the constant_pool; must be of type "CONSTANT_Utf8_info"
            |   u1 minor_version
            |   u1 major_version
            |   u1 aid_length
            |   u1 aid[aid_length]
            | }


        Class Information:
        ==================

        | class_info {
        |   u1 token
        |   u2 access_flags
        |   u2 name_index
        |
        |   u2 export_supers_count
        |   u2 supers[export_supers_count]
        |
        |   u1 export_interfaces_count
        |   u2 interfaces[export_interfaces_count]
        |
        |   u2 export_fields_count
        |   field_info fields[export_fields_count]
        |
        |   u2 export_methods_count
        |   method_info methods[export_methods_count]
        |
        |   u1 CAP22_inheritable_public_method_token_count
        |                                    ----> (since Export File format 2.3)
        | }


            Field Information:
            ==================

            | field_info {
            |   u1 token
            |   u2 access_flags
            |   u2 name_index
            |   u2 descriptor_index
            |   u2 attributes_count
            |   attribute_info attributes[attributes_count]
            | }


                | attribute_info {
                |   u2 attribute_name_index
                |   u4 attribute_length
                |   u1 info[attribute_length]
                | }


            Method Information:
            ===================

            | method_info {
            |   u1 token
            |   u2 access_flags
            |   u2 name_index
            |   u2 descriptor_index
            | }
    """

    def __init__(self):
        pass

    @staticmethod
    def get_access_modifiers(flags):
        modifiers_map = {
            0x0001: "Public",
            0x0010: "Final",
            0x0200: "Interface",
            0x0400: "Abstract",
            0x0800: "Shareable",
            0x1000: "Remote",
            0x0004: "Protected",
            0x0008: "Static",
        }

        return "-".join(
            modifier for bit, modifier in modifiers_map.items() if flags & bit
        )

    @staticmethod
    def parse_method_info(input_file):

        return {
            "token": b2i(input_file.read(1)),
            "access_flags": EXP2JSON.get_access_modifiers(b2i(input_file.read(2))),
            "name_index": b2i(input_file.read(2)),
            "descriptor_index": b2i(input_file.read(2)),
        }

    @staticmethod
    def parse_field_info(input_file):

        field_info = {
            "token": b2i(input_file.read(1)),
            "access_flags": EXP2JSON.get_access_modifiers(b2i(input_file.read(2))),
            "name_index": b2i(input_file.read(2)),
            "descriptor_index": b2i(input_file.read(2)),
            "attribute_count": b2i(input_file.read(2)),
        }

        field_info["attributes"] = list()

        for _ in range(field_info["attribute_count"]):
            attribute = {
                "attribute_name_index": b2i(input_file.read(2)),
                "attribute_length": b2i(input_file.read(4)),
            }
            attribute["info"] = input_file.read(attribute["attribute_length"]).hex()
            field_info["attributes"].append(attribute)

        return field_info

    def parse_class_info(self, input_file):

        class_info = {
            "token": b2i(input_file.read(1)),
            "access_flags": EXP2JSON.get_access_modifiers(b2i(input_file.read(2))),
            "name_index": b2i(input_file.read(2)),
            "export_supers_count": b2i(input_file.read(2)),
        }

        class_info["supers"] = [
            b2i(input_file.read(2)) for _ in range(class_info["export_supers_count"])
        ]
        class_info["export_interfaces_count"] = b2i(input_file.read(1))
        class_info["interfaces"] = [
            b2i(input_file.read(2))
            for _ in range(class_info["export_interfaces_count"])
        ]

        class_info["export_fields_count"] = b2i(input_file.read(2))
        class_info["fields"] = [
            EXP2JSON.parse_field_info(input_file)
            for _ in range(class_info["export_fields_count"])
        ]

        class_info["export_methods_count"] = b2i(input_file.read(2))
        class_info["methods"] = [
            EXP2JSON.parse_method_info(input_file)
            for _ in range(class_info["export_methods_count"])
        ]

        if self.export_format >= "2.3":
            class_info["CAP22_inheritable_public_method_token_count"] = b2i(
                input_file.read(1)
            )

        return class_info

    def parse_cp_info(self, input_file):
        TAG_MAP = {
            1: "1/UTF8",
            3: "3/Integer",
            7: "7/Classref",
            13: "13/Package",
        }

        entry = dict()

        tag_int = b2i(input_file.read(1))
        entry["tag"] = TAG_MAP.get(tag_int, f"{tag_int} (Unknown Tag)")

        match entry["tag"]:
            case "1/UTF8":
                length = b2i(input_file.read(2))
                bytes = input_file.read(length).decode()
                entry.update(
                    {
                        "length": length,
                        "bytes": bytes,
                    }
                )

            case "3/Integer":
                entry.update({"bytes": input_file.read(4).hex()})

            case "7/Classref":
                entry.update(
                    {
                        "name_index": b2i(input_file.read(2)),
                    }
                )

            case "13/Package":
                flags = ["0/None", "1/Library"][b2i(input_file.read(1))]
                name_index = b2i(input_file.read(2))
                minor_version = b2i(input_file.read(1))
                major_version = b2i(input_file.read(1))
                version = f"{major_version}.{minor_version}"
                aid_length = b2i(input_file.read(1))
                aid = input_file.read(aid_length).hex()
                entry.update(
                    {
                        "flags": flags,
                        "name_index": name_index,
                        "version": version,
                        "aid_length": aid_length,
                        "aid": aid,
                    }
                )

            case default:
                raise ValueError(f"Invalid Tag value in constant_pool! => {tag_int}")

        return entry

    def parse(self, file_path):

        export_file = dict()
        with open(file_path, "rb") as input_file:

            assert "00facade" == input_file.read(4).hex().lower()
            export_file["magic"] = "00facade"

            minor_version = b2i(input_file.read(1))
            major_version = b2i(input_file.read(1))
            export_file["version"] = f"{major_version}.{minor_version}"
            self.export_format = export_file["version"]

            export_file["constant_pool_count"] = b2i(input_file.read(2))
            export_file["constant_pool"] = list()
            for _ in range(export_file["constant_pool_count"]):
                export_file["constant_pool"].append(self.parse_cp_info(input_file))

            export_file["this_package"] = b2i(input_file.read(2))

            if export_file["version"] >= "2.3":
                export_file["referenced_package_count"] = b2i(input_file.read(1))
                export_file["referenced_packages"] = [
                    b2i(input_file.read(2))
                    for _ in range(export_file["referenced_package_count"])
                ]

            export_file["export_class_count"] = b2i(input_file.read(1))
            export_file["classes"] = list()
            for _ in range(export_file["export_class_count"]):
                export_file["classes"].append(self.parse_class_info(input_file))

        return json.dumps(export_file, indent=2)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Read a EXP file and generate corresponding parsed JSON representation."
    )
    parser.add_argument("exp_path", help="Path to the input EXP file")
    parser.add_argument(
        "--output",
        "-o",
        help="Optional output file path and name (default: autogenerated with timestamp)",
    )
    parser.add_argument(
        "--overwrite", 
        action="store_true",
        help="Overwrite existing file if the provided output file name is not unique."
    )
    parser.add_argument(
        "--print", "-p", action="store_true", help="Print the JSON in the output"
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    args = parse_arguments()

    if not os.path.isfile(args.exp_path):
        logger.error(f"File '{args.exp_path}' does not exist.")
        sys.exit(1)

    if args.output:
        if os.path.exists(args.output) and not args.overwrite:
            logger.error(f"Error: Output file '{args.output}' already exists. Use --overwrite or provide a new name.")
            sys.exit(1)
        output_file_name = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exp_name = os.path.splitext(os.path.basename(args.exp_path))[0]
        output_file_name = f"output{os.path.sep}{timestamp}_{exp_name}_exp.json"

    try:
        exp2json = EXP2JSON()
        json_exp = exp2json.parse(args.exp_path)

        if args.print:
            # with "print" it's more convenient to redirect to output file 
            print(json_exp)

        # If "-p" is used, writing occurs only when "-o" is also specified.
        if args.output or not args.print:
            with open(output_file_name, "w") as f:
                f.write(json_exp)
                logger.info(f"Parsed EXP file written to '{output_file_name}'")

    except Exception as e:
        logger.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
