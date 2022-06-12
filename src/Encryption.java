import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Encryption {

    /*Method takes in a secret key, a string to encrypt, and an ivSpec*/
    public static byte[] symmetricEncrypt(SecretKey key, byte[] text, IvParameterSpec ivSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{

        //get IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //encryption
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        //need to have a method to generate a ivspec
        byte[] encryptedOutput = cipher.doFinal(text);
        return encryptedOutput;
    }


    /*Method takes in a secret key, a byte array to decrypt, and an ivSpec */
    public static byte[] symmetricDecrypt(SecretKey key, byte[] text,IvParameterSpec ivSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
        //get IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedOutput = cipher.doFinal(text);
        return decryptedOutput;
    }

    /*Method takes in a string to encrypt and a public key */
    public static byte[] asymmetricEncrypt(byte[] textByte, PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        //encrypt
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key); //private key or public key
        byte[] encryptedText = cipher.doFinal(textByte);
        return encryptedText;
    }

    /*Method takes in a byte array to decrypt and a public/private key */
    public static byte[] asymmetricDecrypt(byte[] text,Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        //dencrypt
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key); //public key or private key
        byte[] decryptedText = cipher.doFinal(text);
        // String result = new String(encryptedText);
        return decryptedText;
    }

    /**
     * The method is used to encrypt the session key generated for each message sent
     * @param recipientPublicKey The recipient public key used as imput for the encryption algorithms
     * @param secretKey The key that is being encrypted
     * @return encrypted secret key byte array
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encryptSessionKey(PublicKey recipientPublicKey, SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        byte[] secretKeyEncoding = secretKey.getEncoded();
        byte[] secretKeyEncodingEncrypt = Encryption.asymmetricEncrypt(secretKeyEncoding, recipientPublicKey);
        return secretKeyEncodingEncrypt;
    }

    /**
     * This function is used to generate the short lived secret key
     * @return Secret Key used for message++signed hash encryption
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey secretKeyGeneration() throws NoSuchAlgorithmException{
        KeyGenerator secretKeyGen = KeyGenerator.getInstance("AES");
        secretKeyGen.init(128);
        SecretKey secretKey = secretKeyGen.generateKey();
        return secretKey;
    }

    /**
     * Signing and generating a hash with the algorithm SHA256withRSA
     * @param messageData data to be signed
     * @param sendPrivateKey input for the signing
     * @return signed hash
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static byte [] signedData(byte[] messageData, PrivateKey sendPrivateKey) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException{
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(sendPrivateKey);
        sig.update(messageData);
        byte[] signatureBytes = sig.sign();
        return signatureBytes;
    }
}