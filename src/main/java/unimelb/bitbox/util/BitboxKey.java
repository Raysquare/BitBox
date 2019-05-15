package unimelb.bitbox.util;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import org.apache.commons.io.IOUtils;

import com.google.common.base.Splitter;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;
import com.google.common.base.Charsets;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

    public static byte[] EncryptSecretKey (PublicKey pub, SecretKey secretKey)
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
        return key;
    }

    public static SecretKey DecryptSecretKey(byte[] content, PrivateKey privateKey) {
        SecretKey key = null;
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


    public static PrivateKey getPrivateKey(String path)
            throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(path));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
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
     * @param args
     * @throws Exception
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
        System.out.println("the public key: "+pubkeyencoded);

        // Encrypting our secret key
        byte[] encrpytedkey = EncryptSecretKey(pubkey,secretKey);
        String encryptedkeystr = Base64.getEncoder().encodeToString(encrpytedkey);
        System.out.println("the encrypted key: \n"+encryptedkeystr);

        // A der file of private key convert to Java private key class
        PrivateKey prikey =getPrivateKey("keyfiles/private_key.der");
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
