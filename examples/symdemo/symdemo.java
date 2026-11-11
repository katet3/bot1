package symdemo;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * A deliberately small symbolic-execution demonstration for Java Card Classic.
 *
 * Suggested package AID: F053594D44454D4F, version 1.0.
 * Suggested applet/instance AID: F053594D44454D4F01.
 * Applet class: symdemo.SymbolicDemoApplet.
 *
 * Short APDUs only, basic logical channel, no command chaining.
 * CLA=80, P1=P2=00. All incoming data must arrive in the first receive call;
 * a partial receive is rejected with 6700 for this bounded demonstration.
 * Successful commands return two data bytes followed by SW=9000. Use Le=02.
 *
 * INS=10, Lc=08: find eight bytes reaching targetRare(); response 10 01.
 * INS=20, Lc=02: a positive big-endian amount, from 1 to 10000.
 *                Normal acceptance: 20 00; overflow bug: 20 01.
 * INS=30, Lc=02: prove that targetImpossible() cannot be reached.
 *                Its hypothetical response would be 30 01.
 *
 * There is no mutable application state: every command starts independently.
 * The limit check in runOverflow() is INTENTIONALLY INCORRECT for the demo.
 * No cryptographic security is claimed for the rare-input checks.
 *
 * Keep the generated CAP, JCA and EXP files when converting this source.
 * The source alone does not fix CAP method offsets or constant-pool tokens.
 */
public final class symdemo extends Applet {
    private static final byte CLA_DEMO = (byte) 0x80;
    private static final byte INS_RARE = (byte) 0x10;
    private static final byte INS_OVERFLOW = (byte) 0x20;
    private static final byte INS_IMPOSSIBLE = (byte) 0x30;

    private static final short START_BALANCE = (short) 30000;
    private static final short BALANCE_LIMIT = (short) 32000;
    private static final short MAX_AMOUNT = (short) 10000;

    private symdemo() {
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        symdemo applet = new symdemo();
        // The first LV field of the installation data contains the instance AID.
        // Use the overload already modelled by the project's Java Card profile.
        applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != CLA_DEMO) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if (buffer[ISO7816.OFFSET_P1] != (byte) 0
                || buffer[ISO7816.OFFSET_P2] != (byte) 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_RARE:
            receiveExact(apdu, (short) 8);
            runRare(apdu);
            return;
        case INS_OVERFLOW:
            receiveExact(apdu, (short) 2);
            runOverflow(apdu);
            return;
        case INS_IMPOSSIBLE:
            receiveExact(apdu, (short) 2);
            runImpossible(apdu);
            return;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void receiveExact(APDU apdu, short expected) {
        byte[] buffer = apdu.getBuffer();
        short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        if (lc != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short received = apdu.setIncomingAndReceive();
        if (received != expected) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    private void runRare(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Unsigned bytes represented as shorts, with concrete buffer indices.
        short a = (short) (buffer[5] & 0x00FF);
        short b = (short) (buffer[6] & 0x00FF);
        short c = (short) (buffer[7] & 0x00FF);
        short d = (short) (buffer[8] & 0x00FF);
        short e = (short) (buffer[9] & 0x00FF);
        short f = (short) (buffer[10] & 0x00FF);
        short g = (short) (buffer[11] & 0x00FF);
        short h = (short) (buffer[12] & 0x00FF);

        if ((short) (a + b) != (short) 220) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (b ^ c) != (short) 0x0058) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (c + d) != (short) 303) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (d ^ e) != (short) 0x00DB) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (e + f) != (short) 253) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (f ^ g) != (short) 0x00B6) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (g + h) != (short) 221) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (a ^ h) != (short) 0x002C) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (a + b + c + d + e + f + g + h) != (short) 997) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        targetRare(apdu); // TARGET 1: generate an APDU reaching this call.
    }

    private void runOverflow(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // Big-endian decoding without shifts or an additional Util API model.
        short high = (short) (buffer[5] & 0x00FF);
        short low = (short) (buffer[6] & 0x00FF);
        short amount = (short) ((short) (high * (short) 256) + low);
        if (amount <= (short) 0 || amount > MAX_AMOUNT) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // INTENTIONAL BUG: narrow to signed short BEFORE checking the limit.
        short proposed = (short) (START_BALANCE + amount);
        if (proposed > BALANCE_LIMIT) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // This is an observation point, not a corrective validation.
        if (proposed < (short) 0) {
            targetOverflow(apdu); // TARGET 2: invalid balance passed the limit.
            return;
        }
        sendResult(apdu, INS_OVERFLOW, (byte) 0x00);
    }

    private void runImpossible(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short x = (short) (buffer[5] & 0x00FF);
        short y = (short) (buffer[6] & 0x00FF);

        // Each pair of conditions is satisfiable, but all three are not.
        // All arithmetic here stays within the positive short range.
        if ((short) (x + y) != (short) 300) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (x ^ y) != (short) 0x008A) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if ((short) (x & y) != (short) 0x0041) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        targetImpossible(apdu); // TARGET 3: prove this call is unreachable.
    }

    private void targetRare(APDU apdu) {
        sendResult(apdu, INS_RARE, (byte) 0x01);
    }

    private void targetOverflow(APDU apdu) {
        sendResult(apdu, INS_OVERFLOW, (byte) 0x01);
    }

    private void targetImpossible(APDU apdu) {
        sendResult(apdu, INS_IMPOSSIBLE, (byte) 0x01);
    }

    private void sendResult(APDU apdu, byte scenario, byte outcome) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = scenario;
        buffer[1] = outcome;
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }
}
