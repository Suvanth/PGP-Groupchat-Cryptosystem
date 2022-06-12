import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.operator.OperatorCreationException;

/*
 * Class to test the methods for certificate generation and validation of Certificate class
 */
public class TestCertificate {
    
    public static void main(String[] args) throws CertificateException, OperatorCreationException, NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, IOException {
        Certificates.test();
    }
}
