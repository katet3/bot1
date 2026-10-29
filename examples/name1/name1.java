/*
 * @file  name1.java
 * @version v1.0
 * Package AID: 4A617661436172644F53 
 * Applet AID:  4A617661436172644F5302
 * @brief The ALgorithm of DES Sample Code in JavaCard API Specification
 * @comment The purpose of this example is only used to show the usage of API functions and there is no practical significance.
 * @copyright Copyright(C) 2016 JavaCardOS Technologies Co., Ltd. All rights reserved.
 */

package name1 ;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.*;
import javacardx.crypto.*;

public class name1 extends Applet
{
	private static final byte INS_SET_DES_KEY              = (byte)0x20;
    private static final byte INS_SET_DES_ICV              = (byte)0x21;
    private static final byte INS_DO_DES_CIPHER            = (byte)0x22;
    
    private byte desKeyLen;
    private byte[] desKey;
    private byte[] desICV;

    private Cipher desEcbCipher;
    private Cipher desCbcCipher;

    private Key tempDesKey2;
    private Key tempDesKey3;
    
    public name1()
    {
        desKey = new byte[32];
        desICV = new byte[8];
        desKeyLen = 0;
		//Create a DES ECB/CBS object instance of the DES algorithm.
        desEcbCipher = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
        desCbcCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
		//Creates uninitialized TDES cryptographic keys for signature and cipher algorithms. 
        tempDesKey3 = KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_3KEY, false);

        JCSystem.requestObjectDeletion();
    }
    
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new name1().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_SET_DES_KEY:
        	//SET_DES_KEY
            setDesKey(apdu, len);
            break;
        case INS_SET_DES_ICV:
        	//SET_DES_ICV
            setDesICV(apdu, len);
            break;
        case INS_DO_DES_CIPHER:
        	//DO_DES_CIPHER
            doDesCipher(apdu, len);
            break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	//Set the key of TDES Encrypt/Decrypt
    private void setDesKey(APDU apdu, short len)
    {
        byte[] buffer = apdu.getBuffer();
        byte keyLen = 0;
        switch (buffer[ISO7816.OFFSET_P1])
        {
        case (byte)0x01: // The length of key is 16 bytes
            if (len != 16)
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            keyLen = (byte)16;
            break;
        case (byte)0x02:
            if (len != 24) // The length of key is 24 bytes
            {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            keyLen = (byte)24;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            break;
        }

        JCSystem.beginTransaction();
        //Copy the incoming TDES Key value to the global variable 'desKey'
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, desKey, (short)0, len);
        desKeyLen = keyLen;
        JCSystem.commitTransaction();
    }
	
	//Set DES ICV, ICV is the initial vector
    private void setDesICV(APDU apdu, short len)
    {
        if (len != 8)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Copy the incoming ICV value to the global variable 'desICV'
        Util.arrayCopy(apdu.getBuffer(), ISO7816.OFFSET_CDATA, desICV, (short)0, (short)8);
    }

	//Get the key that set into the 'desKey' in setDesKey() function, and return the DESKey object.
	//The plain text length of input key data is 8 bytes for DES, 16 bytes for 2-key triple DES and 24 bytes for 3-key triple DES. 
    private Key getDesKey()
    {
        Key tempDesKey = null;
        switch (desKeyLen)
        {
        case (byte)16:
            tempDesKey = tempDesKey2;
            break;
        case (byte)24:
            tempDesKey = tempDesKey3;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            break;
        }
        //Set the 'desKey' key data value into the internal representation
        ((DESKey)tempDesKey).setKey(desKey, (short)0);
        return tempDesKey;
    }

	//DES algorithm encrypt and decrypt
    private void doDesCipher(APDU apdu, short len)
    {
    	//In Des algorithm the byte length to be encrypted/decrypted must be a multiple of 8
        if (len <= 0 || len % 8 != 0)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] buffer = apdu.getBuffer();
        Key key = getDesKey();
        byte mode = buffer[ISO7816.OFFSET_P1] == (byte)0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
        Cipher cipher = buffer[ISO7816.OFFSET_P2] == (byte)0x00 ? desEcbCipher : desCbcCipher;
        //Initializes the 'cipher' object with the appropriate Key and algorithm specific parameters.
        //DES algorithms in CBC mode expect a 8-byte parameter value for the initial vector(IV)
        if (cipher == desCbcCipher)
        {
            cipher.init(key, mode, desICV, (short)0, (short)8);
        }
        else
        {
            cipher.init(key, mode);
        }
		//This method must be invoked to complete a cipher operation. Generates encrypted/decrypted output from all/last input data.
        cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
        apdu.setOutgoingAndSend((short)0, len);
    }

}