package de.hwr.rsakey.pem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static java.security.Security.addProvider;

public class RsaKeyPairPem {

    private RsaKeyPairPem() {}

    static {
        addProvider(new BouncyCastleProvider());
    }


    /**
     *
     * @param keySize
     * @return PPKeys object that contain private and public keys
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public static PPKeys createKeys(int keySize) throws NoSuchAlgorithmException, IOException {
        PPKeys keys = new PPKeys();

        // Create keyPair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Convert PrivateKey to PEM format
        StringWriter privateWrite = new StringWriter();
        JcaPEMWriter privatePemWriter = new JcaPEMWriter(privateWrite);
        privatePemWriter.writeObject(keyPair.getPrivate());
        privatePemWriter.close();
        keys.setPrivatekey(privateWrite.toString());
        privatePemWriter.close();
        privateWrite.close();

        // Convert PublicKey to PEM format
        StringWriter publicWrite = new StringWriter();
        JcaPEMWriter publicPemWriter = new JcaPEMWriter(publicWrite);
        publicPemWriter.writeObject(keyPair.getPublic());
        publicPemWriter.close();
        keys.setPublicKey(publicWrite.toString());
        publicPemWriter.close();
        publicWrite.close();

        return keys;
    }


    /**
     *
     * @param publicKeyPem
     * @param plainText
     * @return encrypted string
     */
    public static String encrypt(String publicKeyPem,String plainText) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Read PEM Format
        PemReader pemReader = new PemReader(new StringReader(publicKeyPem));
        byte[] content = pemReader.readPemObject().getContent();
        // Get X509EncodedKeySpec format
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(content);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKeySecret = kf.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeySecret);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return new String(Base64.encode(encryptedBytes));
    }


    /**
     *
     * @param privateKeyPem
     * @param encryptedString
     * @return decrypted string
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(String privateKeyPem,String encryptedString) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Read PEM Format
        PemReader pemReader = new PemReader(new StringReader(privateKeyPem));
        PemObject pemObject = pemReader.readPemObject();
        pemReader.close();

        // Get PKCS8EncodedKeySpec for decrypt
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKeySecret = kf.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKeySecret);
        return new String(cipher.doFinal(Base64.decode(encryptedString)), StandardCharsets.UTF_8);

    }
}
