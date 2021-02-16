package io.github.nosuchcompany.pgplug.sign;

import io.github.nosuchcompany.pgplug.utils.PGPUtils;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

import static io.github.nosuchcompany.pgplug.utils.PGPUtils.*;
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
    void testSigned_alternateStreamedHappyPath() throws Exception {
        String privateKeyDest = TEST_FOLDER + "/testSigned_HappyPath.prv";
        String publicKeyDest = TEST_FOLDER + "/testSigned_HappyPath.pub";
        String encryptedFileDest = TEST_FOLDER + "/testSigned_HappyPath_enc.test";
        String decryptedFileDest = TEST_FOLDER + "/testSigned_HappyPath_dec.test";
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

        ByteArrayOutputStream designed;
        designed = SignedFileProcessor.verifyFile(
                new ByteArrayInputStream(readContentIntoByteArray(new File(encryptedSignedFileDest))),
                new FileInputStream(publicKeyDest));
        decrypt(
                designed.toByteArray(),
                readContentIntoByteArray(new File(privateKeyDest)),
                new FileOutputStream(decryptedFileDest),
                pass );

        assertNotNull(designed);
        assertEquals(clearData.length, readContentIntoByteArray(new File(decryptedFileDest)).length);
        assertEquals(new String(clearData), new String(readContentIntoByteArray(new File(decryptedFileDest))));
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

    private static byte[] readContentIntoByteArray(File file)
    {
        FileInputStream fileInputStream = null;
        byte[] bFile = new byte[(int) file.length()];
        try
        {
            //convert file into array of bytes
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(bFile);
            fileInputStream.close();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return bFile;
    }

}