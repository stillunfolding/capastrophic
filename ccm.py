#!/usr/bin/python3

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from utils.cardreader import CardReader
from utils.scp import SCP
from utils.const import const
from json2cap import JSON2CAP
from pathlib import Path

logger = logging.getLogger("CCM")
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t[LOGMSG] :::: %(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


class CCM:  # Card Content Manager
    def __init__(self, card_connection):
        self.card_connection = card_connection
        self.secure_channel_session = SCP(self.card_connection)

    def send_apdu(self, apdu):
        return self.card_connection.send_apdu(apdu)

    def send_secure_apdu(self, apdu):
        return self.secure_channel_session.send_secure_apdu(apdu)

    def mutual_auth(
        self,
        sec_level=const.SCP_SECLEVEL_NO_SECURITY_LEVEL,
        static_enc=const.KEY_40_4F_16B,
        static_mac=const.KEY_40_4F_16B,
        static_dek=const.KEY_40_4F_16B,
        sd_aid=None,
    ):
        return self.secure_channel_session.mutual_auth(
            sec_level, static_enc, static_mac, static_dek, sd_aid
        )

    def _get_cap_file_path(self, json_file_path, json_conversion_mode):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file_name = os.path.splitext(os.path.basename(json_file_path))[0]
        cap_file_path = (
            f"output{os.path.sep}CCM_generated_{timestamp}_{json_file_name}_json.cap"
        )

        try:
            with open(json_file_path, "r", encoding="utf-8") as input_file:
                json_data = json.load(input_file)

            json2cap = JSON2CAP()
            success = json2cap.build_cap(
                json_data, cap_file_path, json_conversion_mode
            )  # only default conversion mode: SHALLOW

            if success:
                logger.info(
                    f"Auto-Generated CAP file is available under '{cap_file_path}'"
                )
                return cap_file_path
            else:
                logger.error("Automatic CAP file generation failed!")
                sys.exit(1)

        except (OSError, json.JSONDecodeError) as e:
            logger.exception(f"Failed to process JSON file '{json_file_path}': {e}")
            sys.exit(1)

        except Exception as e:
            logger.exception(f"Unexpected error during automatic CAP generation: {e}")
            sys.exit(1)

    def load_cap(
        self,
        file_path,
        cap_aid,  # package AID in compact format
        sd_aid=[],
        load_params=[],
        components_order=[],
        apply_order_to_head=True,
        chunk_sizes=[],
        apply_sizes_to_head=True,
        from_json=False,
        json_conversion_mode="shallow",
    ):

        if from_json:
            cap_file_path = self._get_cap_file_path(file_path, json_conversion_mode)
        else:
            cap_file_path = file_path

        return self.secure_channel_session.load_cap(
            cap_file_path,
            cap_aid,
            sd_aid,
            load_params,
            components_order,
            apply_order_to_head,
            chunk_sizes,
            apply_sizes_to_head,
        )

    def install_applet(
        self,
        cap_aid,  # package AID in compact format
        applet_class_aid,  # applet AID within a package
        instance_aid,  # to be instanciated applet
        priviledges=[],
        install_params=[],
    ):
        return self.secure_channel_session.install_applet(
            cap_aid, applet_class_aid, instance_aid, priviledges, install_params
        )

    def list_content(self, deprecated_data_structure=False):
        applications_info, packages_info = self.secure_channel_session.list_content(
            deprecated_data_structure
        )

        print()
        print("::: Card Content :::\n")
        for applet in applications_info:
            aid, lifecycle, privilege, assiciated_package = applet
            print(
                f"APP: {bytes(aid).hex().upper()} (LC: {lifecycle}, Priv: {privilege})\n"
            )
            if assiciated_package:
                print(f"\tPKG: {bytes(assiciated_package).hex().upper()}")

        for package in packages_info:
            aid, lifecycle, applet_classes_aids, version = package
            print(
                f"PKG: {bytes(aid).hex().upper()} (LC: {lifecycle}, Version: {version})"
            )
            for aid in applet_classes_aids:
                print(f"\tAPP: {bytes(aid).hex().upper()}")
            print()

    def delete_content(self, aid):
        return self.secure_channel_session.delete_content(aid)


def _hexstring_to_byte_seq(hexstring):
    return bytes.fromhex(hexstring)


def _hexstring_to_int_list(hexstring):
    return list(bytes.fromhex(hexstring))


def parse_arguments():
    # parent parser with common arguments
    common_parser = argparse.ArgumentParser(add_help=False)

    common_parser.add_argument(
        "-x",
        "--skip-settings",
        action="store_true",
        help="Ignore settings.json",
    )
    common_parser.add_argument(
        "-r",
        "--reader",
        help="Specify the smart card reader (e.g., 'ACS ACR38')",
        default=None,
    )
    common_parser.add_argument(
        "-a",
        "--apdu",
        nargs="+",
        default=[],
        type=_hexstring_to_int_list,
        help="APDU command[s] to send to the card (hex format)",
    )

    # parent parser with common arguments for commands (CCM related)
    ccm_command_common_parser = argparse.ArgumentParser(add_help=False)

    ccm_command_common_parser.add_argument(
        "--sec-level",
        choices=[0, 1, 2, 3],
        type=int,
        # default=1
        help="Security Level for secure channel session (default: 1/C-MAC)",  # default is later after checking settings.json!
    )
    ccm_command_common_parser.add_argument(
        "--sd-aid",
        default="",
        type=_hexstring_to_int_list,
        help="Security domain AID",
    )
    ccm_command_common_parser.add_argument(
        "--key-enc",
        default="",  # defualt is set to 40...4F after checking settings.json!
        type=_hexstring_to_byte_seq,
        help="SCP encryption key (default: 40...4F)",
    )
    ccm_command_common_parser.add_argument(
        "--key-mac",
        default="",  # defualt is set to 40...4F after checking settings.json!
        type=_hexstring_to_byte_seq,
        help="SCP MAC key (default: 40...4F)",
    )
    ccm_command_common_parser.add_argument(
        "--key-dek",
        default="",  # defualt is set to 40...4F after checking settings.json!
        type=_hexstring_to_byte_seq,
        help="SCP DEK key (default: 40...4F)",
    )
    ccm_command_common_parser.add_argument(
        "-k",
        "--key",
        default="",
        type=_hexstring_to_byte_seq,
        help="SCP keys (to be used when ENC, MAC, DEK keys are all equal)",
    )
    ccm_command_common_parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List card's content after the CCM operation",
    )

    # parent parser for applet installation optional arguments (used in load and install commands)
    common_install_parser = argparse.ArgumentParser(add_help=False)

    common_install_parser.add_argument(
        "-i",
        "--instance-aid",
        type=_hexstring_to_int_list,
        help="Applet instance AID (in hex; default: applet's class AID)",
    )
    common_install_parser.add_argument(
        "--priv",
        default="00",
        type=_hexstring_to_int_list,
        help="Applet privileges (in hex; default: 00)",
    )
    common_install_parser.add_argument(
        "--install-params",
        type=_hexstring_to_int_list,
        default="",
        help="Installation parameters (in hex; default: nothing)",
    )

    # main parser
    parser = argparse.ArgumentParser(
        description="Card Content Management Tool for GlobalPlatform-compatible Java Cards.\
            Supports mutual authentication, CAP loading, applet installation, deletion,\
                and sending APDU commands (including secure messaging)",
        parents=[common_parser, ccm_command_common_parser],
    )

    parser.add_argument(
        "-s",
        "--secure-apdu",
        action="store_true",
        help="Send APDUs provided with -a/--apdu via SCP",
    )

    parser.set_defaults(command="transmit")

    subparsers = parser.add_subparsers(
        dest="command", help=".:: Card content operation ::."
    )

    # Authentication command
    delete_parser = subparsers.add_parser(
        "auth",
        help="Perform GP mutual authentication",
        parents=[common_parser, ccm_command_common_parser],
    )

    # List command
    delete_parser = subparsers.add_parser(
        "list",
        help="List loaded packages and installed applets",
        parents=[common_parser, ccm_command_common_parser],
    )
    delete_parser.add_argument(
        "--deprecated-struct",
        action="store_true",
        help="GET STATUS for card contents with deprecated data structure (P2.B2=0)",
    )

    # Load command
    load_parser = subparsers.add_parser(
        "load",
        help="Load a CAP/JSON file to the Java card and optionally install applet",
        parents=[common_parser, ccm_command_common_parser, common_install_parser],
    )
    load_parser.add_argument("file", help="Path to the CAP/JSON file to be loaded")
    load_parser.add_argument(
        "-p",
        "--package-aid",
        required=True,
        type=_hexstring_to_int_list,
        help="AID of the package",
    )
    load_parser.add_argument(
        "--asd-aid",
        type=_hexstring_to_int_list,
        default=[],
        help="Associated Security Domain AID (in hex; default: CM/current-SD AID)",
    )
    load_parser.add_argument(
        "--load-params",
        type=_hexstring_to_int_list,
        default="",
        help="load parameters (in hex; optional)",
    )
    load_parser.add_argument(
        "--components-order",
        type=str,
        nargs="+",
        default=[],
        help="list of component names specifying the order of initial or last components in load process",
    )
    load_parser.add_argument(
        "--order-position",
        choices=["head", "tail"],
        default="head",
        help="Indicates whether the components provided in --components-order specifies heading or trailing components",
    )
    load_parser.add_argument(
        "--chunk-sizes",
        type=int,
        nargs="+",
        default=[],
        help="list of integers for the sizes of initial or last chunks of LOAD commands",
    )
    load_parser.add_argument(
        "--size-position",
        choices=["head", "tail"],
        default="head",
        help="Indicates whether the sizes provided in --chunk-sizes specifies heading or trailing LOAD commands sizes",
    )
    load_parser.add_argument(
        "--install", action="store_true", help="Instanciate the applet after loading"
    )
    load_parser.add_argument(
        "-c",
        "--applet-class-aid",
        type=_hexstring_to_int_list,
        help="AID of the applet class for installation (option when --install is used)",
    )
    load_parser.add_argument(
        "-m",
        "--json-conversion-mode",
        choices=["shallow", "deep"],
        default="shallow",
        help="Optional JSON to CAP conversion mode: shallow mode (default) uses 'raw_modified' or 'raw' elements in JSON file, whereas deep mode uses parsed elements.\
            Can be used when input file is provided in JSON format.",
    )

    # Install command
    install_parser = subparsers.add_parser(
        "install",
        help="Instanciate an applet from an already loaded package; or optionally load CAP/JSON first and then instanciate an applet",
        parents=[common_parser, ccm_command_common_parser, common_install_parser],
    )
    install_parser.add_argument(
        "-p",
        "--package-aid",
        type=_hexstring_to_int_list,
        required=True,
        help="AID of the package (in hex)",
    )
    install_parser.add_argument(
        "-c",
        "--applet-class-aid",
        required=True,
        type=_hexstring_to_int_list,
        help="Applet class AID (mandatory when installing an applet from a preloaded package; optional otherwise)",
    )

    # Delete command
    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete an applet or package from the card",
        parents=[common_parser, ccm_command_common_parser],
    )
    delete_parser.add_argument(
        "aid", type=_hexstring_to_int_list, help="AID of the applet/package to delete"
    )

    # Script command
    script_parser = subparsers.add_parser(
        "script",
        help="Execute a sequence of commands from a script/json file",
        parents=[common_parser, ccm_command_common_parser],
    )
    script_parser.add_argument(
        "file",
        help="Path to a script file (JSON) containing a list of commands to execute in order",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # As "parser" object is not available in main()
    if args.command == "load" and args.install:
        if not args.applet_class_aid:
            parser.error(
                "The --install flag requires -c/--applet-class-aid argument to be provided"
            )

    return args


def load_settings():
    settings_path = Path("settings.json")
    if not settings_path.exists():
        return {}
    with settings_path.open() as fp:
        return json.load(fp)


def main():
    args = parse_arguments()
    settings = load_settings()
    card_connection = CardReader()
    reader_name = args.reader or settings.get("common", {}).get("reader", "")
    if not card_connection.connect(reader_name):
        return False

    ccm = CCM(card_connection)

    if args.command or args.secure_apdu:

        sec_level = (
            args.sec_level
            if args.sec_level is not None
            else settings.get("common", {}).get("sec_level", 1)
        )

        if not ccm.mutual_auth(
            sec_level=sec_level,
            static_enc=args.key_enc
            or args.key
            or bytes.fromhex(
                settings.get("common", {}).get("key_enc", const.KEY_40_4F_16B)
            ),
            static_mac=args.key_mac
            or args.key
            or bytes.fromhex(
                settings.get("common", {}).get("key_mac", const.KEY_40_4F_16B)
            ),
            static_dek=args.key_dek
            or args.key
            or bytes.fromhex(
                settings.get("common", {}).get("key_dek", const.KEY_40_4F_16B)
            ),
            sd_aid=args.sd_aid or settings.get("common", {}).get("sd_aid", []),
        ):
            card_connection.disconnect()
            return False

    match args.command:
        case "auth":
            pass  # already done above

        case "load":
            if ccm.load_cap(
                args.file,
                args.package_aid,
                args.asd_aid,  # associate security domain
                args.load_params,
                args.components_order,
                args.order_position == "head",
                args.chunk_sizes,
                args.size_position == "head",
                args.file.lower().endswith(".json"),
                args.json_conversion_mode,
            ):
                if args.install:
                    instance_aid = (
                        args.instance_aid
                        if args.instance_aid
                        else args.applet_class_aid
                    )
                    return ccm.install_applet(
                        args.package_aid,
                        args.applet_class_aid,
                        instance_aid,
                        args.privileges,
                        args.install_params,
                    )
                elif (
                    args.applet_class_aid != args.instance_aid
                ):  # only instance AID provided
                    logger.error(
                        f"Installation requires both --class-aid to be specified"
                    )

        case "install":
            instance_aid = (
                args.instance_aid if args.instance_aid else args.applet_class_aid
            )
            ccm.install_applet(
                args.package_aid,
                args.applet_class_aid,
                instance_aid,
                args.priv,
                args.install_params,
            )

        case "delete":
            ccm.delete_content(args.aid)

        case "list":
            ccm.list_content(args.deprecated_struct)

        case "script":
            logger.error("Script command not implemented yet!")

    # list the contnet if requested using "-l/--list"
    if ccm.secure_channel_session.is_mutually_authenticated and args.list:
        ccm.list_content()

    if args.apdu:
        for apdu in args.apdu:
            # ToDo: command's logical channel shall be compared with the secure channel's logical channel
            if (
                apdu[:3] == [0x00, 0xA4, 0x04]  # Select APDU
                and ccm.secure_channel_session.sec_level
            ):
                logger.info(
                    "SELECT APDU received. Secure channel session security level reset to 'No Security'"
                )
                ccm.secure_channel_session.reset_session()

            ccm.secure_channel_session.send_secure_apdu(apdu)

    return True


if __name__ == "__main__":
    main()
