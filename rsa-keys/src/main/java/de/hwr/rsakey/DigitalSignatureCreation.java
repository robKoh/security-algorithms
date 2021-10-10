package de.hwr.rsakey;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DigitalSignatureCreation {

    private static final Logger LOGGER = Logger.getLogger("DigitalSignatureCreation");


    private static void generateDigitalSignature(String[] args) throws
            IOException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        int index = 0;
        String keyFile = args[index]; index++;
        String dataFile = args[index]; index++;
        String signFile = args[index];

        /* Load private key. */
        File privateKeyFile = new File(RsaKeyPair.FILE_PATH + keyFile);
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        byte[] messageBytes = Files.readAllBytes(Paths.get(RsaKeyPair.FILE_PATH + dataFile));

        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();

        Files.write(Paths.get(RsaKeyPair.FILE_PATH + signFile), digitalSignature);
    }

    public static void main(String[] args) throws Exception {
        if ( args.length != 3 ) {
            LOGGER.log(Level.WARNING, "generate digital signature.");
            LOGGER.log(Level.WARNING, "usage: java pvtKeyFile dataFile signFile");
            System.exit(1);
        }
        generateDigitalSignature(args);
    }
}
