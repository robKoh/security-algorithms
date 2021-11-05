package de.hwr.aes;

import org.assertj.core.api.WithAssertions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

class AESUtilUnitTest implements WithAssertions {

    private static final Logger LOGGER = Logger.getLogger("AESUtilUnitTest");

    @Test
    void givenString_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String input = "Advanced Decryption Standard";
        SecretKey key = AESUtil.generateKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";

        // when
        String cipherText = AESUtil.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AESUtil.decrypt(algorithm, cipherText, key, ivParameterSpec);

        // then
        String msg = String.format("Das Verschlüsseln und Entschlüsseln des Strings \"input\" mit %s hat funktioniert.", algorithm);
        String msgError = String.format("FEHLER! Das Verschlüsseln und Entschlüsseln des Strings " +
                "\"input\" mit %s hat nicht funktioniert.", algorithm);
        Assertions.assertEquals(input, plainText, msgError);
        LOGGER.info(msg);
    }

    @Test
    void givenFile_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        SecretKey key = AESUtil.generateKey(128);
        String algorithm = "AES/CBC/PKCS5Padding";
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        File inputFile = Paths.get("src/test/resources/input.txt")
                .toFile();
        File encryptedFile = new File("src/test/resources/input.encrypted");
        File decryptedFile = new File("src/test/resources/input.decrypted");

        // when
        AESUtil.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        AESUtil.decryptFile(algorithm, key, ivParameterSpec, encryptedFile, decryptedFile);

        // then
        assertThat(inputFile).hasSameTextualContentAs(decryptedFile);
        String msg = "Das Verschlüsseln und Entschlüsseln der Testdatei \"input.txt\" " +
                "mit dem AES-Algorithmus hat funktioniert.";
        LOGGER.info(msg);

        boolean hasDeleted = encryptedFile.delete();
        if (!hasDeleted) throw new FileNotFoundException();
        hasDeleted = decryptedFile.delete();
        if (!hasDeleted) throw new FileNotFoundException();
    }

    @Test
    void givenObject_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IOException, BadPaddingException,
            ClassNotFoundException {
        // given
        Student student = new Student("Robert", 21);
        SecretKey key = AESUtil.generateKey(128);
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";

        // when
        SealedObject sealedObject = AESUtil.encryptObject(algorithm, student, key, ivParameterSpec);
        Student object = (Student) AESUtil.decryptObject(algorithm, sealedObject, key, ivParameterSpec);

        // then
        assertThat(student).isEqualTo(object);
        String msg = "Das Verschlüsseln und Entschlüsseln des Objekts \"student\" " +
                "mit dem AES-Algorithmus hat funktioniert.";
        LOGGER.info(msg);
    }

    @Test
    void givenPassword_whenEncrypt_thenSuccess()
            throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        // given
        String plainText = "www.baeldung.com";
        String password = "baeldung";
        String salt = "12345678";
        IvParameterSpec ivParameterSpec = AESUtil.generateIv();
        SecretKey key = AESUtil.getKeyFromPassword(password, salt);

        // when
        String cipherText = AESUtil.encryptPasswordBased(plainText, key, ivParameterSpec);
        String decryptedCipherText = AESUtil.decryptPasswordBased(cipherText, key, ivParameterSpec);

        // then
        String msg = "Das Verschlüsseln und Entschlüsseln des Strings \"plaintext\" " +
                "mit dem geheimen passwortbasierten Schlüssel hat funktioniert.";
        String msgError = "FEHLER! Das Verschlüsseln und Entschlüsseln des Strings \"plaintext\" " +
                "mit dem geheimen passwortbasierten Schlüssel hat nicht funktioniert.";
        Assertions.assertEquals(plainText, decryptedCipherText, msgError);
        LOGGER.info(msg);
    }
}
