package io.github.nosuchcompany.pgplug.sign;

import io.github.nosuchcompany.pgplug.utils.PGPUtils;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

import static io.github.nosuchcompany.pgplug.utils.PGPUtils.encrypt;
import static io.github.nosuchcompany.pgplug.utils.PGPUtils.readPublicKey;
import static org.junit.jupiter.api.Assertions.*;

class SignedFileProcessorTest {


    public static final String TEST_FOLDER = "test_folder";
    private static final byte[] clearData = "1234567890".getBytes();
    private static final char[] pass = "1234567890".toCharArray();

    @BeforeAll
    static void setupTestPath(){
        File directory = new File(TEST_FOLDER);
        directory.mkdir();
    }

    @AfterAll
    static void cleanUp(){
        File directoryToBeDeleted = new File(TEST_FOLDER);
        deleteDirectory(directoryToBeDeleted);
    }

    @Test
    void testSigned_HappyPath() throws Exception {
        String privateKeyDest = TEST_FOLDER + "/testSigned_HappyPath.prv";
        String publicKeyDest = TEST_FOLDER + "/testSigned_HappyPath.pub";
        String encryptedFileDest = TEST_FOLDER + "/testSigned_HappyPath_enc.test";
        String encryptedSignedFileDest = TEST_FOLDER + "/testSigned_HappyPath_sign.test";

        OutputStream privateOut = new FileOutputStream(privateKeyDest);
        OutputStream publicOut = new FileOutputStream(publicKeyDest);
        PGPUtils.generateKeyPair(privateOut, publicOut, pass);

        OutputStream outputStream = new FileOutputStream(encryptedFileDest);
        InputStream userPublicKeyStream = new FileInputStream(publicKeyDest);
        Set<PGPPublicKey> publicKeys = new HashSet<PGPPublicKey>();
        publicKeys.add(readPublicKey(userPublicKeyStream));

        encrypt(outputStream, clearData, publicKeys);
        SignedFileProcessor.signFile(
                encryptedFileDest,
                new FileInputStream(privateKeyDest),
                new FileOutputStream(encryptedSignedFileDest),
                pass,
                true
        );
        assertTrue(SignedFileProcessor.verifyFile(new FileInputStream(encryptedSignedFileDest),new FileInputStream(publicKeyDest)));
    }

    @Test
    void testSigned_HappyPath_sameFileSignedOutput() throws Exception {
        String privateKeyDest = TEST_FOLDER + "/testSigned_HappyPath_sameFileSignedOutput.prv";
        String publicKeyDest = TEST_FOLDER + "/testSigned_HappyPath_sameFileSignedOutput.pub";
        String encryptedFileDest = TEST_FOLDER + "/testSigned_HappyPath_sameFileSignedOutput_enc.test";
        String encryptedSignedFileDest = TEST_FOLDER + "/testSigned_HappyPath_sameFileSignedOutput_enc.test";

        OutputStream privateOut = new FileOutputStream(privateKeyDest);
        OutputStream publicOut = new FileOutputStream(publicKeyDest);
        PGPUtils.generateKeyPair(privateOut, publicOut, pass);

        OutputStream outputStream = new FileOutputStream(encryptedFileDest);
        InputStream userPublicKeyStream = new FileInputStream(publicKeyDest);
        Set<PGPPublicKey> publicKeys = new HashSet<PGPPublicKey>();
        publicKeys.add(readPublicKey(userPublicKeyStream));

        encrypt(outputStream, clearData, publicKeys);
        SignedFileProcessor.signFile(
                encryptedFileDest,
                new FileInputStream(privateKeyDest),
                new FileOutputStream(encryptedSignedFileDest),
                pass,
                true
        );
        assertTrue(SignedFileProcessor.verifyFile(new FileInputStream(encryptedSignedFileDest),new FileInputStream(publicKeyDest)));
    }

    @Test
    void testSigned_shouldNotVerified() throws Exception {
        String privateKeyDest = TEST_FOLDER + "/testSigned_shouldNotVerified.prv";
        String publicKeyDest = TEST_FOLDER + "/testSigned_shouldNotVerified.pub";
        String encryptedFileDest = TEST_FOLDER + "/testSigned_shouldNotVerified_enc.test";
        String encryptedSignedFileDest = TEST_FOLDER + "/testSigned_shouldNotVerified_sign.test";

        OutputStream privateOut = new FileOutputStream(privateKeyDest);
        OutputStream publicOut = new FileOutputStream(publicKeyDest);
        PGPUtils.generateKeyPair(privateOut, publicOut, pass);

        String badPrivateKeyDest = TEST_FOLDER + "/bad.prv";
        String badPublicKeyDest = TEST_FOLDER + "/bad.pub";

        OutputStream badPrivateOut = new FileOutputStream(badPrivateKeyDest);
        OutputStream badPublicOut = new FileOutputStream(badPublicKeyDest);
        PGPUtils.generateKeyPair(badPrivateOut, badPublicOut, pass);

        OutputStream outputStream = new FileOutputStream(encryptedFileDest);
        InputStream userPublicKeyStream = new FileInputStream(publicKeyDest);
        Set<PGPPublicKey> publicKeys = new HashSet<PGPPublicKey>();
        publicKeys.add(readPublicKey(userPublicKeyStream));

        encrypt(outputStream, clearData, publicKeys);
        SignedFileProcessor.signFile(
                encryptedFileDest,
                new FileInputStream(privateKeyDest),
                new FileOutputStream(encryptedSignedFileDest),
                pass,
                true
        );
        assertFalse(SignedFileProcessor.verifyFile(new FileInputStream(encryptedSignedFileDest),new FileInputStream(badPublicKeyDest)));
    }

    private static void deleteDirectory(File directoryToBeDeleted){
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        directoryToBeDeleted.delete();
    }

}