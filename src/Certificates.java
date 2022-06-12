import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.*;
import java.math.BigInteger;
import java.security.cert.*;
import java.util.*;
import java.io.*;

public class Certificates {
    
    private static PrivateKey CAPrivateKey;
    private static PublicKey CAPublicKey;

    /**
     * Generates the root certificate for Certificate Authority (CA) and signs it with its own private key
     * @param keyPair public and private key of CA
     * @return certficate CA root certificate
     */
    public static X509Certificate generateCACertificate(RSA keyPair) throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, KeyStoreException, IOException {
        CAPrivateKey = keyPair.getPrivate();
        CAPublicKey = keyPair.getPublic();
        
        Calendar certExpireDate = Calendar.getInstance();
        certExpireDate.add(Calendar.YEAR, 1);

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=CA Root Certificate"),
                BigInteger.ONE,
                new Date(),
                certExpireDate.getTime(),
                new X500Name("CN=CA Root Certificate"),
                SubjectPublicKeyInfo.getInstance(CAPublicKey.getEncoded())
        );
        //Create and sign certificate
        X509CertificateHolder CAcertHolder = certificateBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").build(CAPrivateKey));
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(CAcertHolder);
        //createKeyStore(certificate);

        return certificate;
    }

     /**
     * Generates a client certificate and signs it with CA private key
     * @param clientKey public key of client
     * @param clientName client username
     * @return certficate Client certificate
     */
    public static X509Certificate generateClientCertificate(PublicKey clientKey, String clientName) throws CertificateException, OperatorCreationException, KeyStoreException, NoSuchAlgorithmException, FileNotFoundException, IOException {
        Calendar certExpireDate = Calendar.getInstance();
        certExpireDate.add(Calendar.YEAR, 1);

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                new X500Name("CN="+clientName),
                BigInteger.ONE,
                new Date(),
                certExpireDate.getTime(),
                new X500Name("CN="+clientName),
                SubjectPublicKeyInfo.getInstance(clientKey.getEncoded())
        );
        //Create and sign certificate
        X509CertificateHolder certHolder = certificateBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").build(CAPrivateKey));
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
        //storeCertificate(certificate, clientName);

        return certificate;
    }

    /**
     * Validates client certificate with CA private key to determine if public key belongs to client
     * @param certificate certifcate of client
     * @param caPublicKey CA Public Key
     * @return boolean value for whether certifcate is valid or not
     */
    public static boolean validateCertificate(X509Certificate certificate, PublicKey caPublicKey){
        
        try {
            certificate.verify(caPublicKey);
            return true;
        } 
        catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            return false;
        }  
    }

    /**
     * Generates a client certificate and signs it with a fake CA private key
     * @param certificate certifcate of client
     * @param fakeCAKey Fake CA's Private Key
     * @param clientName client username
     * @return certficate Client certificate
     */
    public static X509Certificate generateFakeCertificate(PublicKey clientKey, PrivateKey fakeCAKey, String clientName) throws CertificateException, OperatorCreationException, KeyStoreException, NoSuchAlgorithmException, FileNotFoundException, IOException {
        Calendar certExpireDate = Calendar.getInstance();
        certExpireDate.add(Calendar.YEAR, 1);

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                new X500Name("CN="+clientName),
                BigInteger.ONE,
                new Date(),
                certExpireDate.getTime(),
                new X500Name("CN="+clientName),
                SubjectPublicKeyInfo.getInstance(clientKey.getEncoded())
        );
        //Create and sign certificate
        X509CertificateHolder certHolder = certificateBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").build(fakeCAKey));
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
        //storeCertificate(certificate, clientName);

        return certificate;
    }


    /*
     * test the methods of the class
     */
    public static void test() throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, IOException {
        // create and generate Server/CA key pair and root certificate
        RSA keyPair = new RSA();
        X509Certificate caCert = generateCACertificate(keyPair);
        System.out.println("CA certificate: "+caCert.toString());
        System.out.println();
        // create and client1 key pair and signed certificate
        RSA keyPairClient1 = new RSA();
        X509Certificate c1Cert = generateClientCertificate(keyPairClient1.getPublic(), "client1");
        System.out.println("Client 1 certificate: "+c1Cert.toString());
        System.out.println();
        // create and client2 key pair and signed certificate
        RSA keyPairClient2 = new RSA();
        X509Certificate c2Cert = generateClientCertificate(keyPairClient2.getPublic(), "client2");
        System.out.println("Client 2 certificate: "+c2Cert.toString());
        System.out.println();

        RSA fakeCA = new RSA();
        RSA keyPairClient3 = new RSA();
        X509Certificate c3Cert = generateFakeCertificate(keyPairClient3.getPublic(), fakeCA.getPrivate() ,"client3");
        System.out.println("Client 3 certificate: "+c3Cert.toString());
        System.out.println();

        System.out.println("Client 1 public key valid with CA: "+validateCertificate(c1Cert, keyPair.getPublic()));
        System.out.println("Client 2 public key valid with CA: "+validateCertificate(c1Cert, keyPair.getPublic()));
        System.out.println("Client 3 public key valid with CA: "+validateCertificate(c3Cert, keyPair.getPublic()));
    }

}
