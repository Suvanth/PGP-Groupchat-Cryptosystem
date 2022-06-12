import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.ArrayList;
import org.bouncycastle.operator.OperatorCreationException;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Server {

    private final ServerSocket serverSocket;
    public static ArrayList<ClientInfo> clients = new ArrayList<ClientInfo>();
    private static RSA keyPair;
    private static X509Certificate CACertificate;
    public static PublicKey CAPublicKey;

    public Server(ServerSocket serverSocket) throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, KeyStoreException, IOException {
        this.serverSocket = serverSocket;
        keyPair = new RSA();
        CAPublicKey = keyPair.getPublic();
        // creates root certificate
        CACertificate = Certificates.generateCACertificate(keyPair);
        System.out.println("LOG: CA Root certificate generated");
        System.out.println();
    }

    public void startServer()throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        try {
            // Listen for connections, from clients, on port 100.
            System.out.println("Server started. Waiting for 3 clients to join...");
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();
                ClientHandler clientHandler = new ClientHandler(socket);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            closeServerSocket();
        }
    }

    public void closeServerSocket() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Create the server socket and start the sever, accepting any requests from clients and parsing that into the clientHandler
    public static void main(String[] args) throws IOException, CertificateException, OperatorCreationException, NoSuchAlgorithmException, KeyStoreException {
        ServerSocket serverSocket = new ServerSocket(1234);
        Server server = new Server(serverSocket);
        try {
            server.startServer();
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
        }
    }

}
