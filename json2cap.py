#!/usr/bin/python3

import argparse
from datetime import datetime
import json
import os
import re
from zipfile import ZipFile, ZipInfo, ZIP_STORED

from misc.template import MANIFEST_MF, JAVACARD_XML, APPLET_XML


# remove the comments, spaces, etc.
def clean_hex_string(input_str):
    # Remove content within (), <>, and []
    input_str = re.sub(r"\(.*?\)", "", input_str)
    input_str = re.sub(r"\[.*?\]", "", input_str)

    # Remove non-hex characters (keep only 0-9 and a-f/A-F)
    hex_only = re.sub(r"[^0-9a-fA-F]", "", input_str)

    return hex_only


class JSON2CAP:
    CONVERTION_TYPE_DEEP = "deep"  # based on the parsed elements in the JSON struct
    CONVERTION_TYPE_SHALLOW = (
        "shallow"  # based on raw elements (hex values) in the JSON struct
    )

    def __init__(self):
        pass

    def build_cap(
        self,
        json_cap,
        cap_file_name,
        conversion_mode=CONVERTION_TYPE_SHALLOW,
        packagename="helloworldPackage",
    ):
        if conversion_mode == self.CONVERTION_TYPE_SHALLOW:
            with ZipFile(cap_file_name, "w", ZIP_STORED) as cap_zip:
                for component_name in json_cap.keys():
                    info = ZipInfo(f"{packagename}/javacard/{component_name}")
                    info.compress_type = ZIP_STORED
                    info.create_system = (
                        0  # to be compatible with JCDK generated CAP files.
                    )
                    info.external_attr = (
                        0  # to be compatible with JCDK generated CAP files.
                    )
                    info.create_version = (
                        10  # to be compatible with JCDK generated CAP files.
                    )
                    component_data = bytes.fromhex(
                        clean_hex_string(
                            json_cap[component_name].get(
                                "raw_modified"
                            )  # due to "or", in case of having empty "raw_modified", the value of "raw" is used
                            or json_cap[component_name]["raw"]
                        )
                    )
                    cap_zip.writestr(info, component_data)
                    print(f"Added {component_name}")

                # Some installers may require the following files as well,
                # however, this is not the case for the tools that I worked
                # with. Hence, they are commented out by default. In case of
                # uncommenting, the contents shall ba checked to be valid for
                # the applet.

                # info = ZipInfo(f"META-INF/MANIFEST.MF")
                # info.compress_type = ZIP_STORED
                # info.create_system = 0
                # info.external_attr = 0
                # cap_zip.writestr(info, MANIFEST_MF)

                # info = ZipInfo(f"META-INF/javacard.xml")
                # info.compress_type = ZIP_STORED
                # info.create_system = 0
                # info.external_attr = 0
                # cap_zip.writestr(info, JAVACARD_XML)

                # info = ZipInfo(f"APPLET-INF/applet.xml")
                # info.compress_type = ZIP_STORED
                # info.create_system = 0
                # info.external_attr = 0
                # cap_zip.writestr(info, APPLET_XML)

            return True
        else:
            print("Deep mode not implmeneted yet!")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Read a JSON representaiton of a CAP file and generate corresponding CAP file."
    )
    parser.add_argument("json_path", help="Path to the input JSON file")
    parser.add_argument("--output", "-o", help="Optional name for the output file")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["shallow", "deep"],
        default="shallow",
        help="Optional conversion mode: shallow mode (default) uses 'raw' elements in JSON file, whereas deep mode uses parsed elements.",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.json_path):
        print(f"Error: File '{args.json_path}' does not exist.")
        exit(1)

    if args.output:
        output_file_name = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_name = ".".join(args.json_path.split(os.path.sep)[-1].split('.')[:-1])
        output_file_name = f"output{os.path.sep}{timestamp}_{json_name}_json.cap"

    try:
        input_file = open(args.json_path, "r", encoding="utf-8")
        json_cap = json.load(input_file)
        input_file.close()

        json2cap = JSON2CAP()
        if json2cap.build_cap(json_cap, output_file_name, args.mode):
            print(f"Generated CAP file is available under '{output_file_name}'")
        else:
            print("Error: conversion failed!")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
