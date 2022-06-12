import java.io.Serializable;
import java.net.InetAddress;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import org.bouncycastle.operator.OperatorCreationException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Wrapper class for some specific client info
 */
public class ClientInfo implements Serializable {
    private int port;
    private InetAddress address;
    private PublicKey publicKey;
    private String username;
    private X509Certificate certificate;
    private boolean trust;

    public ClientInfo(String user, PublicKey KU) throws CertificateException, OperatorCreationException, KeyStoreException, NoSuchAlgorithmException, FileNotFoundException, IOException {
        this.username = user;
        this.publicKey = KU;
        this.trust = false;
        // creates client certificate
        this.certificate = Certificates.generateClientCertificate(KU, username);
        System.out.println("LOG: "+username+" certificate generated");
        System.out.println();
    }

    /**
     * gets port number
     * 
     * @return int
     */
    public int getPort() {
        return port;
    }

    /**
     * gets internet address
     * 
     * @return InetAddress
     */
    public InetAddress getAddress() {
        return address;
    }

    /**
     * gets public key
     * 
     * @return publicKey
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * gets user name
     * 
     * @return username
     */
    public String getUsername() {
        return username;
    }


    /**
     * gets user certificate
     * 
     * @return certificate
     */
    public X509Certificate getCertificate(){
        return certificate;
    }

    /**
     * sets the variable for if the public key can be trusted
     */
    public void trustPublicKey(){
        trust = true;
    }

    /**
     * gets boolean value for if public key can be public key 
     * 
     * @return trust
     */
    public boolean isTrusted() {
        return trust;
    }
}
