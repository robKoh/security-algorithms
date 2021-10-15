package de.hwr.rsakey.pem;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

class TestGeneratingRsaKeyPairPem {

    private static final Logger LOGGER = Logger.getLogger("TestGeneratingRsaKeyPairPem");

    @Test
    void verifiyEncryptingAndDecrypting() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException,
            IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String text = "Schönes Wetter.";
        PPKeys keys = RsaKeyPairPem.createKeys(2048);

        String encrypedText = RsaKeyPairPem.encrypt(keys.getPublicKey(), text);
        String decrypedText = RsaKeyPairPem.decrypt(keys.getPrivatekey(), encrypedText);
        Assertions.assertEquals(text, decrypedText, "FAILURE! Es wurde nicht richtig verschlüsselt oder entschlüsselt.");
        String msg = String.format("Der Text \"%s\" wurde erfolgreich verschlüsselt und wieder entschlüsselt.", text);
        LOGGER.info(msg);
    }
}
