import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SessionCipher {

    private Cipher sessionCipher;

    private SessionKey Key;
    private IvParameterSpec Init_Value;

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Key = key;
        sessionCipher = Cipher.getInstance("AES/CTR/Nopadding");

        byte[] ivbytes = new byte[sessionCipher.getBlockSize()];
        new SecureRandom().nextBytes(ivbytes);
        Init_Value = new IvParameterSpec(ivbytes);
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException {
        Key = key;
        sessionCipher = Cipher.getInstance("AES/CTR/Nopadding");
        Init_Value = new IvParameterSpec(ivbytes);
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return Key;
    }

    /*
     * Return the SessionCipher
     */
    public Cipher getCipher() { return sessionCipher; }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return Init_Value.getIV();
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws InvalidAlgorithmParameterException, InvalidKeyException {
        sessionCipher.init(Cipher.ENCRYPT_MODE, Key.getSecretKey(), Init_Value);
        CipherOutputStream outputStream = new CipherOutputStream(os, sessionCipher);
        return outputStream;
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) throws InvalidAlgorithmParameterException, InvalidKeyException {
        sessionCipher.init(Cipher.ENCRYPT_MODE, Key.getSecretKey(), Init_Value);
        CipherInputStream inputStream = new CipherInputStream(inputstream, sessionCipher);
        return inputStream;
    }
}
