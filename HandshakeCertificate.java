import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {

    X509Certificate cer;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        cer = (X509Certificate) certificateFactory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        //certbytes = Base64.getDecoder().decode(certbytes);
        InputStream file = new ByteArrayInputStream(certbytes);
        cer = (X509Certificate) certificateFactory.generateCertificate(file);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        String certbytes;
        certbytes = Base64.getEncoder().encodeToString(cer.getEncoded());
        return certbytes.getBytes();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return cer;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        X509Certificate ca = cacert.getCertificate();
        ca.checkValidity();
        cer.checkValidity();
        ca.verify(ca.getPublicKey());
        cer.verify(ca.getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        char[] info = cer.toString().toCharArray();
        String CN = "";
        int i;
        for (i = 0; i+2 < info.length ; i++ ){
            if ( info[i] == 'C' && info[i+1] == 'N' && info[i+2] == '='){
                break;
            }
        }
        i = i + 3;
        while( info[i] != ',' ){
            CN = CN + info[i++];
        }
        return CN;
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
        char[] info = cer.toString().toCharArray();
        String EMAIL = "";
        int i;
        for (i = 0; i+2 < info.length ; i++ ){
            if ( info[i] == 'S' && info[i+1] == 'S' && info[i+2] == '='){
                break;
            }
        }
        i = i + 3;
        while( info[i] != ',' ){
            EMAIL = EMAIL + info[i++];
        }
        return EMAIL;
    }
}
