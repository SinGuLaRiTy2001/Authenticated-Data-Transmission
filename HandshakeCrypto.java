import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.Base64;


public class HandshakeCrypto {

	PublicKey publicKey;
	PrivateKey privateKey;

	Boolean isPrivate;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		isPrivate = false;

		X509Certificate certificate = handshakeCertificate.getCertificate();

		publicKey = certificate.getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
		isPrivate = true;

		String privateKeyPEM = Base64.getEncoder().encodeToString(keybytes);
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
		privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
		byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

		KeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		KeyFactory factory = KeyFactory.getInstance("RSA");

		privateKey = factory.generatePrivate(keySpec);
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if (isPrivate)
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		else
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(ciphertext);
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if (isPrivate)
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		else
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(plaintext);
    }
}
