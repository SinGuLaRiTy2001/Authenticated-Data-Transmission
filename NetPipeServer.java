import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.util.*;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.text.SimpleDateFormat;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    HandshakeMessage Client_Hello;
    HandshakeMessage Server_Hello;
    HandshakeMessage Session;

    private HandshakeCertificate Client_cert;
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

    public void Hello_exchange(String ca_path, String cert_path) throws Exception {

        /* =================================== RECEIVE HELLO =================================== */

        Client_Hello = HandshakeMessage.recv(socket);
        int standard_code = HandshakeMessage.MessageType.CLIENTHELLO.getCode();
        if (Client_Hello.getType().getCode() != standard_code) {
            throw new Exception("Unexpected message!");
        }

        System.out.println("[RECV] Client Hello - BEGIN");

        instream = new FileInputStream(ca_path);
        HandshakeCertificate CA_cert = new HandshakeCertificate(instream);
        Client_cert = new HandshakeCertificate(Base64.getDecoder().decode(Client_Hello.getParameter("Certificate")));
        Client_cert.verify(CA_cert);

        System.out.println("[RECV] Client Hello - END");

        /* =================================== SEND HELLO ====================================== */

        System.out.println("[SEND] Server Hello - BEGIN");

        instream = new FileInputStream(cert_path);
        X509Certificate Server_cert = new HandshakeCertificate(instream).getCertificate();
        Server_Hello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        Server_Hello.putParameter("Certificate", Base64.getEncoder().encodeToString(Server_cert.getEncoded()));
        Server_Hello.send(socket);

        System.out.println("[SEND] Server Hello - END");
    }

    public void Finish_exchange(String key) throws Exception {

        /* =================================== SEND FINISH ===================================== */

        HandshakeMessage Server_Finish = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        System.out.println("[SEND] Server Finish - BEGIN");

        HandshakeDigest serverDigest = new HandshakeDigest();

        instream = new FileInputStream(key);
        HandshakeCrypto serverCrypto = new HandshakeCrypto(instream.readAllBytes());

        serverDigest.update(Server_Hello.getBytes());

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Server_Finish.putParameter("Signature", Base64.getEncoder().encodeToString(serverCrypto.encrypt(serverDigest.digest())));
        Server_Finish.putParameter("TimeStamp", Base64.getEncoder().encodeToString(serverCrypto.encrypt(dateFormat.format(Calendar.getInstance().getTime())
                                                                                                                        .getBytes(StandardCharsets.UTF_8))));

        Server_Finish.send(socket);
        System.out.println("[SEND] Server Finish - END");

        /* =================================== RECEIVE FINISH ================================== */

        HandshakeMessage Client_Finish = HandshakeMessage.recv(socket);
        Validate_MessageType(Client_Finish, HandshakeMessage.MessageType.CLIENTFINISHED);

        System.out.println("[RECV] Client Finish - BEGIN");

        HandshakeCrypto clientCrypto = new HandshakeCrypto(Client_cert);

        HandshakeDigest clientDigest_cmp = new HandshakeDigest();
        clientDigest_cmp.update(Client_Hello.getBytes());
        clientDigest_cmp.update(Session.getBytes());

        byte[] clientDigest = clientCrypto.decrypt((Base64.getDecoder().decode(Client_Finish.getParameter("Signature"))));
        if (!clientDigest_cmp.Validate_Digest(clientDigest)) {
            throw new Exception("Message has been modified!");
        }

        dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timeStamp_local = dateFormat.format(Calendar.getInstance().getTime());
        long TimeStamp_local = dateFormat.parse(timeStamp_local).getTime() / 1000;

        byte[] timeStamp_byte = clientCrypto.decrypt((Base64.getDecoder().decode(Client_Finish.getParameter("TimeStamp"))));
        String timeStamp_received = new String(timeStamp_byte, StandardCharsets.UTF_8);
        long TimeStamp_received = dateFormat.parse(timeStamp_received).getTime() / 1000;

        System.out.println("Received Timestamp: "+ timeStamp_received + "\n"
                            + "Local Timestamp: "+ timeStamp_local);

        if ((Math.abs(TimeStamp_received - TimeStamp_local) >= TimeStamp_INTERVAL)) {
            throw new Exception("Timestamp verification failed!");
        }

        System.out.println("[RECV] Client Finish - END");
    }

    public NetPipeServer(String cacert, String usercert, String key) throws Exception {

        /* =================================== HELLO =========================================== */

        Hello_exchange(cacert, usercert);

        /* =================================== SESSION ========================================= */

        Session = HandshakeMessage.recv(socket);
        Validate_MessageType(Session, HandshakeMessage.MessageType.SESSION);

        System.out.println("[RECV] Client Session - BEGIN");

        instream = new FileInputStream(key);
        HandshakeCrypto serverSession = new HandshakeCrypto(instream.readAllBytes());

        SessionKey keyDecrypted = new SessionKey(serverSession.decrypt(Base64.getDecoder().decode(Session.getParameter("SessionKey"))));
        byte[] IVDecrypted = serverSession.decrypt(Base64.getDecoder().decode(Session.getParameter("SessionIV")));

        Session_Encrypt = new SessionCipher(keyDecrypted, IVDecrypted);
        Session_Encrypt.getCipher().init(Cipher.DECRYPT_MODE, keyDecrypted.getSecretKey(), new IvParameterSpec(IVDecrypted));
        Session_Decrypt = new SessionCipher(keyDecrypted, IVDecrypted);
        Session_Decrypt.getCipher().init(Cipher.ENCRYPT_MODE, keyDecrypted.getSecretKey(), new IvParameterSpec(IVDecrypted));

        System.out.println("[RECV] Client Session - END");

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
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws Exception {
        parseArgs(args);
        ServerSocket serverSocket = null;

        String cacert = arguments.get("cacert");
        String usercert = arguments.get("usercert");
        String key = arguments.get("key");

        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        NetPipeServer server = new NetPipeServer(cacert, usercert, key);
        try {
            InputStream  socket_in = server.Session_Decrypt.openDecryptedInputStream(socket.getInputStream());
            OutputStream socket_out = server.Session_Encrypt.openEncryptedOutputStream(socket.getOutputStream());
            Forwarder.forwardStreams(System.in, System.out, socket_in, socket_out, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
