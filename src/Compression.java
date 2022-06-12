import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.*;

/**
 * The Compression class is a utility class with methods used for the compression and decompression of the Hash and Message components.
 * The class also has methods to split the hash and message components from the transmitted message.
 */
public class Compression {
    /**
     * The compress function takes in a data byte array that will be compressed
     * @param data data to be compressed
     * @return compressed byte array
     * @throws IOException
     */
    public static byte[] compress(byte[] data) throws IOException{
        try {
         ByteArrayOutputStream output = new ByteArrayOutputStream();
         DeflaterOutputStream compresser = new DeflaterOutputStream(output);
         compresser.write(data);
         compresser.finish();
         byte [] outputArr = output.toByteArray();
         return outputArr;   
        } 
        catch (Exception e) {
            System.out.println(e);
        }
     return null;
     }
 
     /**
      * Decompress the compressed message. Has to be lossless
      * @param compressedByteArr byte array of compressed message
      * @return decompressed byte array
      * @throws IOException
      */
     public static byte[] decompress(byte[] compressedByteArr) throws IOException{
         ByteArrayOutputStream out = new ByteArrayOutputStream();
         InflaterOutputStream inflater = new InflaterOutputStream(out);
         inflater.write(compressedByteArr);
         inflater.finish();
         return out.toByteArray();
     }
    
}