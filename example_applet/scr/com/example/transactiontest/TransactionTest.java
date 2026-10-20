package transaction_test;


import javacard.framework.*;

public class TransactionTest extends Applet{
    private static final byte INS_EXCEPTION = 0x01;
    private static final byte INS_ATOM_COPY = 0x02;
    private static final byte INS_GET_VAR = 0x03;
    private static final byte INS_FILL_ARRAY = 0x04;
    private static final byte INS_COPY_ARRAY = 0x05;
    private static final byte INS_GET_APDU_BYTE = 0x06;
    private static final byte INS_SET_INT = 0x07;
    private static final byte INS_NEW_ARRAY = 0x08;
    private static final byte INS_NATIVE_METHOD = 0x09;
    private static final byte INS_CYCLIC_TEST = 0x0A;
    private static final byte INS_GC_CALL = 0x0B;
    private static final byte INS_PUT_STATIC= 0x0C;

    short var = 0;
    byte[] array = new byte[4096];

    byte[] reserve = new byte[256];

    static short static_var = 0;
    static byte[] stat_array;

    static OwnerPIN pin;
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new TransactionTest();
    }

    protected TransactionTest() {

        register();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        if (selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
            return;
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte lc = buffer[ISO7816.OFFSET_LC];
        byte p1 = buffer[ISO7816.OFFSET_P1];

        if (cla != 0x00) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch(ins) {
            case INS_EXCEPTION:
                byte a = (byte) (1/0);
                var = 0x1234;
                break;
            case INS_ATOM_COPY:
                JCSystem.beginTransaction();
                Util.setShort(buffer,(short)0, var);
                JCSystem.commitTransaction();
                break;
            case INS_GET_VAR:
                apdu.setOutgoing();
                apdu.setOutgoingLength((short)2);
                buffer[0] = (byte) (var & 0xFF);
                buffer[1] = (byte) ((var >>8) &0xFF);
                apdu.sendBytes((short) 0, (short) 2);
                break;
            case INS_FILL_ARRAY:
                byte i = 0;
                JCSystem.beginTransaction();
                for(i=0; i < 1; i++) {
                    Util.arrayFillNonAtomic(array, (short)0, (short)4096, p1);
                }
                JCSystem.commitTransaction();
                break;
            case INS_COPY_ARRAY:

                // for(k=1; k<10; k++){
                    for(short j=0; j < (short)255; j++) {
                        reserve[j] = (byte)j;
                    }
                // }
                JCSystem.beginTransaction();
                Util.arrayCopy(reserve, (short) 0, array, (short)0, (short)256);
                JCSystem.commitTransaction();
                break;
            case INS_GET_APDU_BYTE:
                byte b = buffer[(short)0xFF9D];
                buffer[(short)0xFF9C] = 0x57;
                break;
            case INS_SET_INT:
                int abc = 0x12345678;
                break;
            case INS_NEW_ARRAY:
                byte[] local = new byte[1024];
                break;
            case INS_NATIVE_METHOD:
                my_native_method((byte)0, (byte)1, (byte)2);
                break;
            case INS_CYCLIC_TEST:
                short k = 0;
                for(k=0; k < 1000; k++) {
                    JCSystem.beginTransaction();
                    Util.arrayCopy(reserve, (short) 0, array, (short)0, (short)256);
                    JCSystem.commitTransaction();
                    if(k%100 == 0) {
                        continue;
                    }
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short)2);
                    buffer[0] = (byte) (k & 0xFF);
                    buffer[1] = (byte) ((k >>8) &0xFF);
                    apdu.sendBytes((short) 0, (short) 2);
                }
                break;
            case INS_GC_CALL:
                JCSystem.requestObjectDeletion();
                break;
            case INS_PUT_STATIC:
                static_var = (short) 0x30000;
                break;
        }

        byte[] tempBuf = JCSystem.makeTransientByteArray((byte)10, JCSystem.CLEAR_ON_DESELECT);
        APDU apd ;
        apd = apdu;
        byte[] abc = new byte[0x10];
        APDU[] ab = new APDU[0x09];
        abc[3] = 0x23;

        pin = new OwnerPIN((byte)3, (byte) 5);
        stat_array = new byte[0x05];
        stat_array[0] = 0x04;
    }

    public void my_native_method(byte a, byte b, byte c) {
        byte d = 0;
        byte e = 0;
        byte f = 0;
        byte g = 0;
        byte h = 0;

        byte i = 0;
        byte j = 0;
        byte k = 0;
        byte l = 0;
        byte m = 0;
        
        byte n = 0;
        byte o = 0;
        byte p = 0;
        byte q = 0;
        byte r = 0;

        // Для теста необходимо модифицировать CAP файл, установив для этого метода флаг ACC_NATIVE
        Util.arrayCopy(reserve, (short) 0, array, (short)0, (short)256);
    } 
}
