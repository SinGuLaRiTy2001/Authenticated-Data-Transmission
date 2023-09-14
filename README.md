# NetPipe Project: Authenticated Data Transmission

> This is a one-man course project requiring JAVA implementation.

NetPipe starts with a handshake phase where client and server authenticate each other and establish a session key for encrypting the TCP connection. The handshake phase is based on public-key cryptography, and the client and the server start by exchanging certificates. This has two purposes:

- Authentication The client and server verify the signature of the other party's certificate. As a part of the handshake protocol, each party will encrypt information with its private key. By verifying that this information can be decrypted with the (validated) public key in the certificate, each party can authenticate the other side.

- Session key exchange A session key is generated, and the exchange of the key is protected by encrypting it with public-key encryption.
NetPipe uses a simple PKI with a monopoly model. The client has one CA that it trusts to sign the server's certificate, and vice versa.

# Files for Project Assignment "NetPipe"

- `README.md` This file. It is in in Markdown format. You can view it as a text file, or use a Markdown preview tool (there are plenty). 
- `NetPipeClient.java` is a working client for the NetPipe application, without security.
- `NetPipeServer.java` is a working server for the NetPipe application, without security.
- `Arguments.java` is a simple parser for command line arguments. It is used by NetPipeClient and NetPipeServer. 
- `Forwarder.java` is a class with two threads to forward data between streams. It is used by NetPipeClient and NetPipeServer.
- `HandshakeMessage.java` is a class with methods and declarations for the message exchange between client and server during the handshake phase. Use it to implement the handshake protocol. (It is *not* used by any of other classes, since they do not support security.)


