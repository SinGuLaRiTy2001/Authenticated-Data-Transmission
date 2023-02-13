import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {

    public SecretKey AES_Key;

    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        KeyGenerator Key_Gen = KeyGenerator.getInstance("AES");
        Key_Gen.init(length);
        AES_Key = Key_Gen.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        Integer length = keybytes.length;
        SecretKey temp = new SecretKeySpec(keybytes, 0, length, "AES");
        AES_Key = temp;
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return AES_Key;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return AES_Key.getEncoded();
    }
}

