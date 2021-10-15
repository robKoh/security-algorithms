package de.hwr.rsakey.pem;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

public class Application {

    private static final Logger LOGGER = Logger.getLogger("Application");

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException,
            IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String text = "Schönes Wetter.";
        PPKeys keys = RsaKeyPairPem.createKeys(2048);

        LOGGER.info(keys.getPrivatekey());
        LOGGER.info(keys.getPublicKey());

        String encrypedText = RsaKeyPairPem.encrypt(keys.getPublicKey(), text);
        LOGGER.info(encrypedText);

        String decrypedText = RsaKeyPairPem.decrypt(keys.getPrivatekey(), encrypedText);
        LOGGER.info(decrypedText);
    }
}
