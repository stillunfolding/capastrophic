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

    ZERO_IV_8B = bytes.fromhex("0000000000000000")

    GP_DERIVATION_CONST_ENC_SESSION_KEY = bytes.fromhex("0182")
    GP_DERIVATION_CONST_MAC_SESSION_KEY = bytes.fromhex("0101")
    GP_DERIVATION_CONST_DEK_SESSION_KEY = bytes.fromhex("0181")
