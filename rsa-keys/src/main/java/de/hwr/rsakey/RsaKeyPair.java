package de.hwr.rsakey;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RsaKeyPair {

    private static final Logger LOGGER = Logger.getLogger("RsaKeyPair");
    //FILE_PATH will be different on other systems.
    public static final String FILE_PATH = "D:\\Dokumente-Schule\\HWR\\5. Semester\\Studienarbeit II\\Programme\\" +
            "security-algorithms\\rsa-keys\\src\\main\\java\\de\\hwr\\rsakey\\files\\";


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
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        try (FileOutputStream fos = new FileOutputStream(FILE_PATH + outFile + ".key")) {
            fos.write(privateKey.getEncoded());
        }

        try (FileOutputStream fos = new FileOutputStream(FILE_PATH + outFile + ".pub")) {
            fos.write(publicKey.getEncoded());
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
