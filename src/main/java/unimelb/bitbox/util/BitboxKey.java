package unimelb.bitbox.util;

import com.google.common.base.Charsets;
import com.google.common.base.Splitter;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.Iterables.get;
import static com.google.common.collect.Iterables.size;
import static com.google.common.io.BaseEncoding.base64;


/**
 * There is an example in the Main class (at the bottom)
 * You can run this java by :
 * java -cp target/bitbox-0.0.1-SNAPSHOT-jar-with-dependencies.jar unimelb.bitbox.util.BitboxKey
 * Just have a look then. Talk to me if you have any problems.
 * Ray
 */

public class BitboxKey {

    private static final String SSH_MARKER = "ssh-rsa";

    private ByteSource supplier;

    public BitboxKey(String fileName) {
        this(new File(fileName));
    }

    public BitboxKey(File file) {
        try {
            byte[] data = IOUtils.toByteArray(new FileInputStream(file));
            this.supplier = ByteSource.wrap(data);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public BitboxKey(byte[] data) {
        this.supplier = ByteSource.wrap(data);
    }

    public static PublicKey StringToPublicKey (String keyString) throws Exception{
        byte[] publicKeyBytes = keyString.getBytes();
        RSAPublicKeySpec spec = new BitboxKey(publicKeyBytes).convertToRSAPublicKey();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static PublicKey FileToPublicKey (String path) throws Exception{
        File keyFile = new File(path);
        RSAPublicKeySpec spec = new BitboxKey(keyFile).convertToRSAPublicKey();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static String  KeyEncodedString (SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String KeyEncodedString (PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String KeyEncodedString (PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static SecretKey generateSecretKey() {
        KeyGenerator keyGenerator = null;
        try {
            /*
             * Get KeyGenerator object that generates secret keys for the
             * specified algorithm.
             */
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        /* Initializes this key generator for key size to 256. */
        keyGenerator.init(128);

        /* Generates a secret key */
        SecretKey secretKey = keyGenerator.generateKey();

        return secretKey;
    }

    public static String EncryptSecretKey (PublicKey pub, SecretKey secretKey)
    {
        Cipher cipher = null;
        byte[] key = null;

        try
        {
            // initialize the cipher with the user's public key
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pub );
            key = cipher.doFinal(secretKey.getEncoded());
        }
        catch(Exception e )
        {
            System.out.println ( "exception encoding key: " + e.getMessage() );
            e.printStackTrace();
        }
        return Base64.getEncoder().encodeToString(key);
    }

    public static SecretKey DecryptSecretKey(String secretKey_str, PrivateKey privateKey) {
        SecretKey key = null;
        byte[] content = Base64.getDecoder().decode(secretKey_str);
        try
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            key = new SecretKeySpec( cipher.doFinal(content), "AES" );
            return key;
        } catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static String AES_Encryption (String original_str, SecretKey secretKey){
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/ISO10126Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(original_str.getBytes("UTF-8")));
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static String AES_Decryption (String original_str, SecretKey secretKey){

        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/ISO10126Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(original_str)));

        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }

    }


    public static PrivateKey getPrivateKey(String path) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        File initialFile = new File(path);
        InputStream targetStream = new FileInputStream(initialFile);
        RSAPrivateCrtKeySpec pvtspec = decodeRSAPrivatePKCS1(readAllBase64Bytes(targetStream));
        return factory.generatePrivate(pvtspec);

    }

    /**
     * Converts an openSSH private key to a PKCS#1 standard RSA private key spec
     * Source: https://stackoverflow.com/questions/19365940/convert-openssh-rsa-key-to-javax-crypto-cipher-compatible-format
     * @param encoded byte decoded from input stream
     * @return RSAPrivateCrtKeySpec
     */
    private static RSAPrivateCrtKeySpec decodeRSAPrivatePKCS1(byte[] encoded) {
        ByteBuffer input = ByteBuffer.wrap(encoded);
        if (der(input, 0x30) != input.remaining()) throw new IllegalArgumentException("Excess data");
        if (!BigInteger.ZERO.equals(derint(input))) throw new IllegalArgumentException("Unsupported version");
        BigInteger n = derint(input);
        BigInteger e = derint(input);
        BigInteger d = derint(input);
        BigInteger p = derint(input);
        BigInteger q = derint(input);
        BigInteger ep = derint(input);
        BigInteger eq = derint(input);
        BigInteger c = derint(input);
        return new RSAPrivateCrtKeySpec(n, e, d, p, q, ep, eq, c);
    }

    private static BigInteger derint(ByteBuffer input) {
        int len = der(input, 0x02);
        byte[] value = new byte[len];
        input.get(value);
        return new BigInteger(+1, value);
    }

    private static int der(ByteBuffer input, int exp) {
        int tag = input.get() & 0xFF;
        if (tag != exp) throw new IllegalArgumentException("Unexpected tag");
        int n = input.get() & 0xFF;
        if (n < 128) return n;
        n &= 0x7F;
        if ((n < 1) || (n > 2)) throw new IllegalArgumentException("Invalid length");
        int len = 0;
        while (n-- > 0) {
            len <<= 8;
            len |= input.get() & 0xFF;
        }
        return len;
    }

    private static byte[] readAllBase64Bytes(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        BufferedReader r = new BufferedReader(new InputStreamReader(input, StandardCharsets.US_ASCII));
        Base64.Decoder decoder = Base64.getDecoder();
        while (true) {
            String line = r.readLine();
            if (line == null) break;
            if (line.startsWith("-----")) continue;
            output.write(decoder.decode(line));
        }
        return output.toByteArray();
    }

    /**
     * Converts an SSH public key to a x.509 compliant format RSA public key spec
     * Source: https://github.com/jclouds/jclouds/blob/master/compute/src/main/java/org/jclouds/ssh/SshKeys.java
     * @return RSAPublicKeySpec
     */
    public RSAPublicKeySpec convertToRSAPublicKey() {
        try {
            InputStream stream = supplier.openStream();
            Iterable<String> parts = Splitter.on(' ').split(IOUtils.toString(stream, Charsets.UTF_8));
            checkArgument(size(parts) >= 2 && SSH_MARKER.equals(get(parts,0)), "Bad format, should be: ssh-rsa AAAB3....");
            stream = new ByteArrayInputStream(base64().decode(get(parts, 1)));
            String marker = new String(readLengthFirst(stream));

            checkArgument(SSH_MARKER.equals(marker), "Looking for marker %s but received %s", SSH_MARKER, marker);
            BigInteger publicExponent = new BigInteger(readLengthFirst(stream));
            BigInteger modulus = new BigInteger(readLengthFirst(stream));
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);

            return keySpec;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static byte[] readLengthFirst(InputStream in) throws IOException {
        int[] bytes = new int[]{ in.read(), in.read(), in.read(), in.read() };
        int length = 0;
        int shift = 24;
        for (int i = 0; i < bytes.length; i++) {
            length += bytes[i] << shift;
            shift -= 8;
        }
        byte[] val = new byte[length];
        ByteStreams.readFully(in, val);
        return val;

    }

    /**
     * This main function is showing an example how to use this java file.
     * We will delete it after finishing other parts
     * @param args none
     */
    public static void main(String args[]) throws Exception {

        // Generating AES 128 secret key
        SecretKey secretKey = generateSecretKey();
        String encodedKey = KeyEncodedString(secretKey);
        System.out.println("the original secret key: \n"+encodedKey);

        // A string of public key convert to Java public key class
        String pubkeystr = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWn4S24nw8FGKz7uqSxvOifmYbESoDHualRCBhmU+uzluaYXOr56+1i72A6SiJy4uRtVbrTYWxLLaaPk16mzgDdCWBuMh4oqb1wWV3gnfixLfJeDax6XxpzGN4Gmpk6ErCNtbLw9njW4N6brNv7O0hkvDWUTmjlB0cRKQhCXvfifdXD8HW2A4cOeRFU+vdRVVHGAlEz4ZIQ4/hFEGnLX+ccAUXUPr6cTn6NCpNUmib+SSSm581W10iB8HaIwxyxzhaPiXhEMvY0LtEUw+FhQHvfexnhyi/2zVMs1So3eZQZsUKcXjV3qHq7f7T0PPskXmg1boRW7AHTohalsXJBwvN raydevil@xiruideMacBook-Pro.local";
        PublicKey pubkey = StringToPublicKey(pubkeystr);
        String pubkeyencoded = KeyEncodedString(pubkey);
        System.out.println("the public key: \n"+pubkeyencoded);

        // Encrypting our secret key
        String encrpytedkey = EncryptSecretKey(pubkey,secretKey);
        System.out.println("the encrypted key: \n"+encrpytedkey);

        // A der file of private key convert to Java private key class
        PrivateKey prikey =getPrivateKey("keyfiles/jajaja_privatekey");
        String prikeyencoded = KeyEncodedString(prikey);
        System.out.println("the private key: \n"+prikeyencoded);

        // Decrypting our secret key
        SecretKey newSecretKey = DecryptSecretKey(encrpytedkey,prikey);
        String newSecretkeyEncoded = KeyEncodedString(newSecretKey);
        System.out.println("the decrypted secret key: \n"+newSecretkeyEncoded);

        // Example for how to encrypt and decrypt message
        System.out.println("\nExample:");
        String original_str = "hello world";
        System.out.println("Original message is "+original_str);
        String encrypted_str = AES_Encryption(original_str,secretKey);
        System.out.println("Encrypted message is "+encrypted_str);
        String decrypted_str = AES_Decryption(encrypted_str,secretKey);
        System.out.println("Decrypted message is "+ decrypted_str);
    }
}
