import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.text.SimpleDateFormat;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    HandshakeMessage Client_Hello;
    HandshakeMessage Server_Hello;
    HandshakeMessage Session;

    private HandshakeCertificate Server_cert;
    public SessionCipher Session_Encrypt;
    public SessionCipher Session_Decrypt;

    static Socket socket;

    FileInputStream instream;

    private static final int TimeStamp_INTERVAL = 10;

    public void Validate_MessageType(HandshakeMessage message, HandshakeMessage.MessageType type) throws Exception {
        if (message.getType().getCode() != type.getCode()) {
            throw new Exception("Unexpected message!");
        }
    }

    public void Hello_exchange(String cert_path, String ca_path) throws Exception {

        /* =================================== SEND HELLO ====================================== */

        System.out.println("[SEND] Client Hello - BEGIN");

        instream = new FileInputStream(cert_path);
        X509Certificate Client_cert = new HandshakeCertificate(instream).getCertificate();
        Client_Hello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        Client_Hello.putParameter("Certificate", Base64.getEncoder().encodeToString(Client_cert.getEncoded()));
        Client_Hello.send(socket);

        System.out.println("[SEND] Client Hello - END");

        /* =================================== RECEIVE HELLO =================================== */

        Server_Hello = HandshakeMessage.recv(socket);
        Validate_MessageType(Server_Hello, HandshakeMessage.MessageType.SERVERHELLO);

        System.out.println("[RECV] Server Hello - BEGIN");

        instream = new FileInputStream(ca_path);
        HandshakeCertificate CA_cert = new HandshakeCertificate(instream);
        Server_cert = new HandshakeCertificate(Base64.getDecoder().decode(Server_Hello.getParameter("Certificate")));
        Server_cert.verify(CA_cert);

        System.out.println("[RECV] Server Hello - END");
    }

    public void Finish_exchange(String key) throws Exception {

        /* =================================== RECEIVE FINISH ================================== */

        HandshakeMessage Server_Finish = HandshakeMessage.recv(socket);
        Validate_MessageType(Server_Finish, HandshakeMessage.MessageType.SERVERFINISHED);

        System.out.println("[RECV] Server Finish - BEGIN");

        HandshakeCrypto serverCrypto = new HandshakeCrypto(Server_cert);

        HandshakeDigest serverDigest_cmp = new HandshakeDigest();
        serverDigest_cmp.update(Server_Hello.getBytes());

        byte[] serverDigest = serverCrypto.decrypt((Base64.getDecoder().decode(Server_Finish.getParameter("Signature"))));
        if (!serverDigest_cmp.Validate_Digest(serverDigest)) {
            throw new Exception("Message has been modified!");
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timeStamp_local = dateFormat.format(Calendar.getInstance().getTime());
        long TimeStamp_local = dateFormat.parse(timeStamp_local).getTime() / 1000;

        byte[] timeStamp_byte = serverCrypto.decrypt((Base64.getDecoder().decode(Server_Finish.getParameter("TimeStamp"))));
        String timeStamp_received = new String(timeStamp_byte, StandardCharsets.UTF_8);
        long TimeStamp_received = dateFormat.parse(timeStamp_received).getTime() / 1000;

        System.out.println("Received Timestamp: "+ timeStamp_received + "\n"
                            + "Local Timestamp: "+ timeStamp_local);

        if ((Math.abs((TimeStamp_received - TimeStamp_local)) >= TimeStamp_INTERVAL)) {
            throw new Exception("Timestamp verification failed!");
        }

        System.out.println("[RECV] Server Finish - END");

        /* =================================== SEND FINISH ===================================== */

        HandshakeMessage Client_Finish = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        System.out.println("[SEND] Client Finish - BEGIN");

        HandshakeDigest clientDigest = new HandshakeDigest();

        instream = new FileInputStream(key);
        HandshakeCrypto clientCrypto = new HandshakeCrypto(instream.readAllBytes());

        clientDigest.update(Client_Hello.getBytes());
        clientDigest.update(Session.getBytes());

        dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        Client_Finish.putParameter("Signature", Base64.getEncoder().encodeToString(clientCrypto.encrypt(clientDigest.digest())));
        Client_Finish.putParameter("TimeStamp", Base64.getEncoder().encodeToString(clientCrypto.encrypt(dateFormat.format(Calendar.getInstance().getTime())
                                                                                                                        .getBytes(StandardCharsets.UTF_8))));

        Client_Finish.send(socket);
        System.out.println("[SEND] Client Finish - END");
    }

    public NetPipeClient(String cacert, String usercert, String key) throws Exception {

        /* =================================== HELLO =========================================== */

        Hello_exchange(usercert, cacert);

        /* =================================== SESSION ========================================= */

        System.out.println("[SEND] Client Session - BEGIN");

        HandshakeCrypto clientSession = new HandshakeCrypto(Server_cert);
        Session = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);

        SessionKey Session_key = new SessionKey(128);
        Session_Encrypt = new SessionCipher(Session_key);
        byte[] keyEncrypted =  clientSession.encrypt(Session_key.getKeyBytes());
        byte[] IVEncrypted = clientSession.encrypt(Session_Encrypt.getIVBytes());
        Session_Decrypt = new SessionCipher(Session_key, Session_Encrypt.getIVBytes());
        Session_Decrypt.getCipher().init(Cipher.ENCRYPT_MODE, Session_key.getSecretKey(), new IvParameterSpec(Session_Encrypt.getIVBytes()));

        Session.putParameter("SessionKey", Base64.getEncoder().encodeToString(keyEncrypted));
        Session.putParameter("SessionIV", Base64.getEncoder().encodeToString(IVEncrypted));

        Session.send(socket);
        System.out.println("[SEND] Client Session - END");

        /* =================================== FINISH ========================================== */

        Finish_exchange(key);
    }

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "filename");
        arguments.setArgumentSpec("cacert", "filename");
        arguments.setArgumentSpec("key", "filename");

        try {
            arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws Exception {
        parseArgs(args);

        String host = arguments.get("host");
        String cacert = arguments.get("cacert");
        String usercert = arguments.get("usercert");
        String key = arguments.get("key");

        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        NetPipeClient client = new NetPipeClient(cacert, usercert, key);
        try {
            InputStream socket_in = client.Session_Decrypt.openDecryptedInputStream(socket.getInputStream());
            OutputStream socket_out = client.Session_Encrypt.openEncryptedOutputStream(socket.getOutputStream());
            Forwarder.forwardStreams(System.in, System.out, socket_in, socket_out, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);}
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
