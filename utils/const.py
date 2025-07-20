class const:

    # --------------- For Clean ------------------

    DELETE_APPLET_APDU__CMD_HEADER = list(bytes.fromhex("80e40000"))
    DELETE_PKG_APDU_CMD_HEADER = list(bytes.fromhex("80e40080"))

    # -------------- For SCP ------------------
    KEY_40_4F_16B = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
    KEY_40_4F_32B = KEY_40_4F_16B + KEY_40_4F_16B

    SCP_SECLEVEL_NO_SECURITY_LEVEL = 0b00000000
    SCP_SECLEVEL_C_MAC = 0b00000001
    SCP_SECLEVEL_C_DECRYPTION = 0b00000010

    ZERO_IV_8B = b"\x00" * 8
    ZERO_IV_16B = b"\x00" * 16

    # SCP02
    SCP02_GP_DERIVATION_CONST_ENC_SESSION_KEY = bytes.fromhex("0182")
    SCP02_GP_DERIVATION_CONST_MAC_SESSION_KEY = bytes.fromhex("0101")
    SCP02_GP_DERIVATION_CONST_DEK_SESSION_KEY = bytes.fromhex("0181")

    # SCP03
    SCP03_GP_SEPARATION_INDICATOR = bytes.fromhex("00")

    SCP03_GP_DERIVATION_CONST_CARD_CRYPTOGRAM = bytes.fromhex("00")
    SCP03_GP_DERIVATION_CONST_HOST_CRYPTOGRAM = bytes.fromhex("01")
    SCP03_GP_DERIVATION_CONST_ENC_SESSION_KEY = bytes.fromhex("04")
    SCP03_GP_DERIVATION_CONST_MAC_SESSION_KEY = bytes.fromhex("06")
