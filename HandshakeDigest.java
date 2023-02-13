import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class HandshakeDigest {

    MessageDigest md;

    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() throws NoSuchAlgorithmException {
        md = MessageDigest.getInstance("SHA-256");
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        md.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return md.digest();
    }

    public boolean Validate_Digest(byte[] Digest_cmp) {
        return (Arrays.toString(this.digest()).equals(Arrays.toString(Digest_cmp)));
    }
}
