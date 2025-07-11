import logging
from smartcard.System import readers
from smartcard.util import toHexString
from smartcard.scard import SCARD_UNPOWER_CARD

logger = logging.getLogger("CardReader")
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
logger_formatter = logging.Formatter(
    "%(asctime)s\t%(levelname)-5s\t%(message)s",
    # "%(asctime)s\t%(levelname)-5s\t%(filename)-21s: %(lineno)-3d\t%(funcName)-25s\t%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
stream_handler.setFormatter(logger_formatter)
logger.addHandler(stream_handler)


class CardReader:
    def __init__(self):
        self.connection = None
        self.is_connected = False
        self.cold_atr = None
        self.reader_name = None

    def _set_reader_connection(self, reader):
        self.reader_name = str(reader).replace(" ", "___")
        self.connection = reader.createConnection()
        logger.debug(f"Selected Reader: {reader}")

    def select_reader(self, reader_name=None):
        while True:
            try:
                available_readers = readers()

                if not available_readers:
                    retry = input("No readers found! Retry? (Y/n): ").strip().lower()
                    if retry == "n":
                        return False
                    continue

                if reader_name:
                    #  In certain Windows environments, spaces in reader names are replaced with double underscores (__).
                    sanitized_name = reader_name.replace(" ", "___")
                    matched_readers = [
                        str(reader).replace(" ", "___") for reader in available_readers
                    ]
                    if sanitized_name in matched_readers:
                        index = matched_readers.index(sanitized_name)
                        self._set_reader_connection(available_readers[index])
                        return True
                    else:
                        logger.error(
                            f"Preferred reader '{reader_name}' not found among {available_readers}."
                        )
                        return False
                else:
                    print("\nAvailable Readers:")
                    for idx, reader in enumerate(available_readers):
                        print(f"{idx}: {reader}")

                    try:
                        index = int(
                            input(
                                "\nSelect reader index (-1 to rescan, -2 to exit): "
                            ).strip()
                        )
                        print()
                        
                        if index == -2:
                            return False
                        elif index == -1:
                            continue
                        elif 0 <= index < len(available_readers):
                            self._set_reader_connection(available_readers[index])
                            return True
                        else:
                            logger.warning("Invalid selection.")
                            continue
                    except ValueError:
                        logger.warning("Invalid input. Please enter a number.")
                        continue
            except Exception as e:
                logger.error(f"Error selecting reader: {e}")
                return False

    def connect(self, reader_name=None):
        """Connects to the card using a cold reset."""
        if not self.select_reader(reader_name):
            return False

        while True:
            try:
                self.connection.connect(disposition=SCARD_UNPOWER_CARD)
                self.cold_atr = self.connection.getATR()
                self.is_connected = True
                logger.info(
                    f"Connected to card. ATR: {toHexString(self.cold_atr).replace(' ', '')}"
                )
                return True
            except Exception as e:
                logger.warning(f"No card found or failed to connect: {e}")
                retry = input("Retry? (Y/n): ").strip().lower()
                if retry == "n":
                    return False

    def is_expected_apdu_response(
        self, sw1, sw2, expected_sw, resp_data=None, expected_data=None
    ):
        """Validates the response status words and optionally response data."""
        status = (sw1 << 8) + sw2
        if status != expected_sw:
            return False

        if resp_data and expected_data:
            return resp_data == expected_data

        return True

    def send_apdu(self, command, auto_get_response=True, auto_correct_le=True):
        """Sends an APDU command to the card with optional handling of 0x6C and 0x61 responses."""
        try:
            logger.info(f"APDU Cmd ---> {toHexString(command)}")
            resp_data, sw1, sw2 = self.connection.transmit(command)
            logger.info(f"APDU Res <--- {toHexString(resp_data + [sw1, sw2])}")

            if sw1 == 0x6C and auto_correct_le:
                # Correct Le and resend command
                corrected_command = command[:-1] + [sw2]
                logger.info(f"APDU Cmd (auto) ---> {toHexString(corrected_command)}")
                resp_data, sw1, sw2 = self.connection.transmit(corrected_command)
                logger.info(
                    f"APDU Res (auto) <--- {toHexString(resp_data + [sw1, sw2])}"
                )

            # Handle additional data request
            while auto_get_response and sw1 == 0x61:
                get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
                logger.info(f"APDU Cmd (auto) ---> {toHexString(get_response)}")
                extra_data, sw1, sw2 = self.connection.transmit(get_response)
                logger.info(
                    f"APDU Res (auto) <--- {toHexString(extra_data + [sw1, sw2])}"
                )
                resp_data += extra_data

            return resp_data, sw1, sw2

        except TypeError as e:
            logger.error(f"TypeError during APDU transmission: {e}")
            raise
        except Exception as e:
            logger.error(f"Unhandled exception during APDU transmission: {e}")
            raise

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
                logger.info("Card disconnected successfully.")
            except Exception as e:
                logger.warning(f"Failed to disconnect card: {e}")
