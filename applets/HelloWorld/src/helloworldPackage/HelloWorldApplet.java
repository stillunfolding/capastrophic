package helloworldPackage;

import javacard.framework.*;
import serverPackage.SimpleSI;

public class HelloWorldApplet extends Applet{

    public static void install(byte[] bArray, short bOffset, byte bLength){
        new HelloWorldApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if(selectingApplet())
            return;

        byte[] buf = apdu.getBuffer();

        switch (buf[ISO7816.OFFSET_INS]) {
            case (byte)0x00:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6801);
                }
            break;
            case (byte)0x01:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6802);
                }
            break;
            case (byte)0x02:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6803);
                }
            break;
            case (byte)0x03:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6804);
                }
            break;
            case (byte)0x04:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6805);
                }
            break;
            case (byte)0x05:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6806);
                }
            break;
            case (byte)0x06:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6807);
                }
            break;
            case (byte)0x07:
                try {
                    byte result = (byte)(buf[ISO7816.OFFSET_P2] / buf[ISO7816.OFFSET_P1]);
                } catch (ISOException isoExc) {
                    ISOException.throwIt((short)0x6808);
                }
            break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
    }
}