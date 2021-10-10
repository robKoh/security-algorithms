package de.hwr.rsakey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

class TestGeneratingRsaKeyPair {

    private static final Logger LOGGER = Logger.getLogger("TestGeneratingRsaKeyPair");
    private static final String NAME_OF_KEY_FILES = "secure-rsa-key";
    private static final String NAME_OF_DATA_FILE = "input.txt";
    private static final String NAME_OF_SIGNED_FILE = "signed-input.txt";


    @Test
    void verifyDigitalSignature() throws Exception {
        setEnvironmentForVerifyingDigitalSignature();

        String publicKeyFileName = NAME_OF_KEY_FILES + ".pub";

        File publicKeyFile = new File(RsaKeyPair.FILE_PATH + publicKeyFileName);
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);

        byte[] dataFileBytes = Files.readAllBytes(Paths.get(RsaKeyPair.FILE_PATH + NAME_OF_DATA_FILE));
        signature.update(dataFileBytes);

        byte[] signatureBytes = Files.readAllBytes(Paths.get(RsaKeyPair.FILE_PATH + NAME_OF_SIGNED_FILE));
        boolean isCorrect = signature.verify(signatureBytes);

        Assertions.assertTrue(isCorrect, "FAILED! The digital signature was not correctly generated.");
        LOGGER.log(Level.INFO, "PERFECT! The digital signature was correctly generated.");
    }

    private void setEnvironmentForVerifyingDigitalSignature() throws Exception {
        String[] rsaKeyPairArgs = {"RSA", "2048", NAME_OF_KEY_FILES};
        RsaKeyPair.main(rsaKeyPairArgs);

        String[] digitalSignatureArgs = {NAME_OF_KEY_FILES + ".key", NAME_OF_DATA_FILE, NAME_OF_SIGNED_FILE};
        DigitalSignatureCreation.main(digitalSignatureArgs);
    }
}
