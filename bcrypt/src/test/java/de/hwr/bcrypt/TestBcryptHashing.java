package de.hwr.bcrypt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

class TestBcryptHashing {

    private static final Logger LOGGER = Logger.getLogger("TestBcryptHashing");

    @Test
    void compareOriginalPwWithHashPw() {
        String originalPassword = "Password1234";
        String generatedSecuredPasswordHash = BCrypt.hashpw(originalPassword, BCrypt.gensalt(12));

        boolean matched = BCrypt.checkpw(originalPassword, generatedSecuredPasswordHash);
        String msg = String.format("FAILURE! Das ursprüngliche Passwort \"%s\" stimmt nicht mit dem generierten Hash-Password überein.", originalPassword);
        Assertions.assertTrue(matched, msg);
        LOGGER.info("Das Hashen von Passwörtern mit dem implementierten BCrypt-Algorithmus funktioniert.");
    }
}
