package de.hwr.rsakey;

import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RsaKeyPair {

    private static final Logger LOGGER = Logger.getLogger("RsaKeyPair");
    //FILE_PATH will be different on other systems.
    private static final String FILE_PATH = "D:\\Dokumente-Schule\\HWR\\5. Semester\\Studienarbeit II\\Programme\\" +
            "security-algorithms\\rsa-keys\\src\\main\\java\\de\\hwr\\rsakey\\files\\";
    
    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private static void writeBase64(Writer out, Key key) throws IOException {
        byte[] buf = key.getEncoded();
        out.write(ENCODER.encodeToString(buf));
        out.write("\n");
    }

    private static void generateRsaKeyPair(String[] args) throws NoSuchAlgorithmException, IOException {
        int index = 0;
        String algo = args[index];
        index++;
        int keySize = Integer.parseInt(args[index]);
        index++;
        String outFile = null;
        if ( index < args.length ) outFile = args[index];

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo);

        /* initialize with keySize: typically 2048 for RSA */
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();

        Writer out = null;
        try {
            if ( outFile != null ) out = new FileWriter(FILE_PATH + outFile + ".key");
            else out = new OutputStreamWriter(System.out);

            String privateKeyFormatMsg = "Private key format: " +
                    kp.getPrivate().getFormat();
            LOGGER.log(Level.INFO, privateKeyFormatMsg);
            out.write("-----BEGIN RSA PRIVATE KEY-----\n");
            writeBase64(out, kp.getPrivate());
            out.write("-----END RSA PRIVATE KEY-----\n");

            if ( outFile != null ) {
                out.close();
                out = new FileWriter(FILE_PATH + outFile + ".pub");
            }

            String publicKeyFormatMsg = "Public key format: " +
                    kp.getPublic().getFormat();
            LOGGER.log(Level.INFO, publicKeyFormatMsg);
            out.write("-----BEGIN RSA PUBLIC KEY-----\n");
            writeBase64(out, kp.getPublic());
            out.write("-----END RSA PUBLIC KEY-----\n");
        } finally {
            if ( out != null ) out.close();
        }
    }

    //You have to provide two parameters, the type of algorithm for the KeyPairGenerator and the keysize for algorithm,
    //but you can also provide the filename as optional parameter.
    //For example: "RSA", 2048 and "secure-rsa-key".
    public static void main(String[] args) throws Exception {
        if ( args.length == 0 ) {
            LOGGER.log(Level.WARNING, "usage: java algo keySize [outFileName]");
            System.exit(1);
        }
        generateRsaKeyPair(args);
    }
}
