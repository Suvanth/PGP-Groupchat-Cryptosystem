import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class pgpTests {

    private static final PrintStream out = System.out;
    private static final PrintStream dummy = new PrintStream(new OutputStream() {@Override public void write(int b){} });

    private static boolean globalOutputOn = true;
    public static void toggleOutput() {
        System.setOut((globalOutputOn=!globalOutputOn)?dummy:out);
    }

    public static void toggleOutput(boolean on) {
        globalOutputOn = on;
        System.setOut(on?out:dummy);
    }


    /**
     * Testing that the relevant keys are needed for the pgp encrypt/decrypt process
     * @return true if the valid and invalid keys are detected
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws SignatureException
     * @throws InvalidAlgorithmParameterException
     * @throws IOException
     */
    public static boolean receiveMessageTest() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidAlgorithmParameterException, IOException {
        String plainMessage = "Hello this is valid communication between Alice and Bob";
        String senderUsername = "Alice";
        String receipientUserName = "Bob";
        RSA senderPair = new RSA();
        RSA recipeientPair = new RSA();
        RSA fakeKeyPairs = new RSA();
        toggleOutput(false);
        PGPmessages testMessage= PGPmessages.sendMessage(plainMessage, receipientUserName, senderUsername, senderPair.getPrivate(), recipeientPair.getPublic());
        toggleOutput(true);
        toggleOutput(false);
        String resultAuthentic = PGPmessages.receiveMessage(testMessage, recipeientPair.getPrivate(), senderPair.getPublic());
        String resultFake = PGPmessages.receiveMessage(testMessage, fakeKeyPairs.getPrivate(), senderPair.getPublic());
        toggleOutput(true);
        if(resultAuthentic=="Hello this is valid communication between Alice and Bob" && resultFake=="Invalid key used for asymetric decryption type used:class sun.security.rsa.RSAPrivateCrtKeyImpl"){
            return true;
        }
        return false;
    }

    /**
     * Testing if the secretkey is reconstructed properly
     * @param rsaRecipient
     * @param decryptKey
     * @return true if key is constructed properly
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static boolean secretKeyCosntruction(RSA rsaRecipient,PrivateKey decryptKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("Original Key Generation and Encryption");
        SecretKey secretKeyOriginal = Encryption.secretKeyGeneration();
        byte[] keyByteEncoding = secretKeyOriginal.getEncoded();
        byte[] encryptedKeyEncodding = Encryption.asymmetricEncrypt(keyByteEncoding, rsaRecipient.getPublic());
        System.out.println("Reconstructed key");
        //privateKey used for decryption should be a parameter
        byte[] decryptedKeyEncoding = Encryption.asymmetricDecrypt(encryptedKeyEncodding, decryptKey);
        SecretKey secretKeyRestructured = new SecretKeySpec(decryptedKeyEncoding, 0, decryptedKeyEncoding.length, "AES");
        if(secretKeyOriginal.equals(secretKeyRestructured)){
            System.out.println("Key reconstructed succefully");
            return true;
        }else{
            System.out.println("Key incorrect structure");
            return false;
        }
        
        
    }
    /**
     * Runner method of secret key gen
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static void SecretKeyGenRunner() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        RSA OriginalKeyPair = new RSA();
        secretKeyCosntruction(OriginalKeyPair, OriginalKeyPair.getPrivate());
    }

    /**
     * Testing the writing to common byte arrays to ensure messages are concatenated correctly
     * @return true if it performs correctly
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     */
    public static boolean testingConcatenation() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException{
        RSA senderPair = new RSA();
        String Message ="testing the concatenation methods";
        byte[] messageData = Message.getBytes();
        byte[] shaSignature = Encryption.signedData(messageData, senderPair.getPrivate());
        byte[] messageConcat = new byte[messageData.length+shaSignature.length];//creating new byte array of the combined lengths of the previous arrays
        System.arraycopy(messageData, 0, messageConcat, 0, messageData.length);
        System.arraycopy(shaSignature, 0, messageConcat, messageData.length, shaSignature.length);
        //split array
        int byteArrayLength = messageConcat.length;
        int signatureLength = 128;
        int messageEndIndex = byteArrayLength-signatureLength;
        byte[] messageByteArray = Arrays.copyOfRange(messageConcat, 0, messageEndIndex);
        byte[] signedHash = Arrays.copyOfRange(messageConcat, messageEndIndex, byteArrayLength);
        System.out.println("MESSAGE COMPONENT");
        System.out.println(Arrays.toString(messageData));
        System.out.println(Arrays.toString(messageByteArray));
        System.out.println("HASH COMPONENT");
        System.out.println(Arrays.toString(shaSignature));
        System.out.println(Arrays.toString(signedHash));
        if(Arrays.equals(messageData,messageByteArray) && Arrays.equals(shaSignature,signedHash)){
            System.out.println("Concatenation logic split works");
            return true;
        }else{
            System.out.println("Concatenation logic split does not work");
            return false;
        }
    }

    /**
     * Testing compression ratio and losslessness
     * @return true if losseless
     * @throws IOException
     */
    public static boolean compressionLosslessTest() throws IOException{
        String data = "This is a long sentence to show that the compression can compress lossleslly";
        System.out.println("Original byte array length");
        System.out.println(data.getBytes().length);
        System.out.println("Compressed byte array length");
        byte[] compressedData = Compression.compress(data.getBytes());
        System.out.println(compressedData.length);
        byte[] decompressedData = Compression.decompress(compressedData);
        System.out.println("Decompressed byte array length");
        System.out.println(decompressedData.length);
        String decompressedString = new String(decompressedData);
        if(decompressedString.equals(data)){
            System.out.println("Lossless compression");
            return true;
        }
        System.out.println("false");
        return false;
    }
}