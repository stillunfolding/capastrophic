#!/usr/bin/python3

import argparse
import logging
import sys
from utils.cardreader import CardReader
from utils.scp import SCP
from utils.const import const
from json2cap import clean_hex_string

logger = logging.getLogger("Installer")
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t[LOGMSG] :::: %(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


class Installer:
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
        from_json=False,
    ):
        if from_json:
            pass
        else:
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
        class_aid,  # applet AID within a package
        instance_aid,  # to be instanciated applet
        priviledges=[],
        install_params=[],
    ):
        return self.secure_channel_session.install_applet(
            cap_aid, class_aid, instance_aid, priviledges, install_params
        )

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
        "-r",
        "--reader",
        help="Specify the smart card reader (e.g., 'ACS ACR38')",
        default=None,
    )

    common_parser.add_argument(
        "-a",
        "--apdus",
        nargs="+",
        default=[],
        type=_hexstring_to_int_list,
        help="APDU command to send to the card within secure channel (hex format).",
    )

    common_parser.add_argument(
        "--scp",
        choices=["scp02", "scp03"],
        default="scp02",
        help="Secure channel protocol to use",
    )

    common_parser.add_argument(
        "--sec-level",
        choices=[0, 1, 2, 3],
        type=int,
        default=0,
        help="Security Level for secure channel session (default 0/No-Security)",
    )

    common_parser.add_argument(
        "--sd-aid",
        default="",
        type=_hexstring_to_int_list,
        help="Security domain AID",
    )

    common_parser.add_argument(
        "--key-enc",
        default=const.KEY_40_4F_16B,
        type=_hexstring_to_byte_seq,
        help="SCP encryption key",
    )
    common_parser.add_argument(
        "--key-mac",
        default=const.KEY_40_4F_16B,
        type=_hexstring_to_byte_seq,
        help="SCP MAC key",
    )
    common_parser.add_argument(
        "--key-dek",
        default=const.KEY_40_4F_16B,
        type=_hexstring_to_byte_seq,
        help="SCP DEK key",
    )

    # main parser
    parser = argparse.ArgumentParser(
        description="Card Content Management Tool for GlobalPlatform-compatible Java Cards.\
            Supports mutual authentication, CAP loading, applet installation, deletion,\
                and sending APDU commands (including secure messaging)."
    )

    subparsers = parser.add_subparsers(dest="command", help="Card content operation")

    parser.add_argument(
        "-a",
        "--apdus",
        nargs="+",
        default=[],
        type=_hexstring_to_int_list,
        help="APDU command to send to the card without secure channel (hex format).",
    )

    parser.add_argument(
        "-r",
        "--reader",
        help="Specify the smart card reader (e.g., 'ACS ACR38')",
        default=None,
    )

    # Load command
    load_parser = subparsers.add_parser(
        "load", help="Load a CAP/JSON file to the Java card", parents=[common_parser]
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
        help="Associated Security Domain AID (in hex; default: CM/current-SD AID",
    )

    load_parser.add_argument(
        "--load-params",
        type=_hexstring_to_int_list,
        default="",
        help="load parameters (in hex; optional)",
    )

    load_parser.add_argument(
        "-o",
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
        "-s",
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
        "-c",
        "--class-aid",
        type=_hexstring_to_int_list,
        help="AID of the applet class to instantiate after loading. "
        "Must be used in combination with -i/--instance-aid. "
        "If omitted, the CAP is loaded but no applet is instantiated. ",
    )

    load_parser.add_argument(
        "-i" "--instance-aid",
        type=_hexstring_to_int_list,
        help="AID of the applet to instantiate after loading. "
        "Must be used in combination with -c/--class-aid. "
        "If omitted, the CAP is loaded but no applet is instantiated. ",
    )
    load_parser.add_argument(
        "--privileges",
        default="00",
        type=_hexstring_to_int_list,
        help="Privileges (in hex; default: 00)",
    )
    load_parser.add_argument(
        "--install-params",
        type=_hexstring_to_int_list,
        default="",
        help="Installation parameters (in hex; default: nothing)",
    )

    # Install command
    install_parser = subparsers.add_parser(
        "install",
        help="Instanciate an applet from an existing applet class on the card",
        parents=[common_parser],
    )
    install_parser.add_argument(
        "-p",
        "--package-aid",
        type=_hexstring_to_int_list,
        required=True,
        help="AID of the package containing applet class (in hex)",
    )
    install_parser.add_argument(
        "-c",
        "--class-aid",
        type=_hexstring_to_int_list,
        required=True,
        help="AID of the applet class to be instanciated (in hex)",
    )
    install_parser.add_argument(
        "-i",
        "--instance-aid",
        type=_hexstring_to_int_list,
        help="Applet instance AID (in hex; default: applet's class AID)",
    )
    install_parser.add_argument(
        "--privileges",
        default="00",
        type=_hexstring_to_int_list,
        help="Privileges (in hex; default: 00)",
    )
    install_parser.add_argument(
        "--install-params",
        type=_hexstring_to_int_list,
        default="",
        help="Installation parameters (in hex; default: nothing)",
    )

    # Delete command
    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete an applet or package from the card",
        parents=[common_parser],
    )
    delete_parser.add_argument(
        "aid", type=_hexstring_to_int_list, help="AID of the applet/package to delete"
    )

    # Script command
    script_parser = subparsers.add_parser(
        "script",
        help="Execute a sequence of commands from a script/json file.",
        parents=[common_parser],
    )
    script_parser.add_argument(
        "file",
        help="Path to a script file (JSON) containing a list of commands to execute in order.",
    )

    # Authentication command
    delete_parser = subparsers.add_parser(
        "auth",
        help="Performs Mutual Authentication with the card",
        parents=[common_parser],
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    args = parse_arguments()

    card_connection = CardReader()
    if not card_connection.connect(reader_name=args.reader):
        return False

    installer = Installer(card_connection)

    if args.command:
        if not installer.mutual_auth(
            sec_level=args.sec_level,
            static_enc=args.key_enc,
            static_mac=args.key_mac,
            static_dek=args.key_dek,
            sd_aid=args.sd_aid,
        ):
            card_connection.disconnect()
            return False

    match args.command:
        case "auth":
            pass  # already done above

        case "load":
            if installer.load_cap(
                args.file,
                args.package_aid,
                args.asd_aid,  # associate security domain
                args.load_params,
                args.components_order,
                args.order_position == "head",
                args.chunk_sizes,
                args.size_position == "head",
                args.file.lower().endswith(".json"),
            ):
                if args.class_aid and args.instance_aid:  # both arguments provided
                    return installer.install_applet(
                        args.package_aid,
                        args.class_aid,
                        instance_aid,
                        args.privileges,
                        args.install_params,
                    )
                elif args.class_aid != args.instance_aid:  # one argument not provided
                    logger.error(
                        f"Installation requires both --class-aid and --instance-aid to be specified."
                    )

        case "install":
            instance_aid = args.instance_aid if args.instance_aid else args.class_aid
            installer.install_applet(
                args.package_aid,
                args.class_aid,
                instance_aid,
                args.privileges,
                args.install_params,
            )

        case "delete":
            installer.delete_content(args.aid)

        case "list":
            pass

        case "script":
            pass

    if args.apdus:
        for apdu in args.apdus:
            if (
                apdu[:3] == [0x00, 0xA4, 0x04]
                and installer.secure_channel_session.sec_level
            ):  # Select APDU
                logger.info(
                    "SELECT APDU received. Secure channel session security level reset to 'No Security'."
                )
                installer.secure_channel_session.reset_session()

            installer.secure_channel_session.send_secure_apdu(apdu)

    return True


if __name__ == "__main__":
    main()
