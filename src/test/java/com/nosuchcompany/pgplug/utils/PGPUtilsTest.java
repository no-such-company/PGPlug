package com.nosuchcompany.pgplug.utils;

import com.nosuchcompany.pgplug.keyPair.KeyPairPGP;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.nosuchcompany.pgplug.utils.PGPUtils.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

class PGPUtilsTest {

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
    void testHappyPath() {
        KeyPairPGP keyPair1 = new KeyPairPGP(pass);
        KeyPairPGP keyPair2 = new KeyPairPGP(pass);

        Set<PGPPublicKey> publicKeys = new HashSet<PGPPublicKey>();
        publicKeys.add(keyPair1.getPGPPublicKey());
        publicKeys.add(keyPair2.getPGPPublicKey());

        ByteArrayOutputStream enc_os = new ByteArrayOutputStream();
        PGPUtils.encrypt(enc_os, clearData, publicKeys);

        byte[] encryptedByteArray = enc_os.toByteArray();
        ByteArrayOutputStream dec_os = new ByteArrayOutputStream();
        PGPUtils.decrypt(encryptedByteArray, keyPair1.getPrivateKey(), dec_os, pass);
        byte[] decryptedByteArray = dec_os.toByteArray();

        assertArrayEquals(clearData, decryptedByteArray);
        assertArrayEquals(clearData, dec_os.toByteArray());

        dec_os = new ByteArrayOutputStream();
        PGPUtils.decrypt(encryptedByteArray, keyPair2.getPrivateKey(), dec_os, pass);
        decryptedByteArray = dec_os.toByteArray();
        assertArrayEquals(clearData, decryptedByteArray);
    }

    @Test
    void test_shouldCreateKeys() throws FileNotFoundException {
        String privateKeyDest = TEST_FOLDER + "/test_shouldCreateKeys.prv";
        String publicKeyDest = TEST_FOLDER + "/test_shouldCreateKeys.pub";

        OutputStream privateOut = new FileOutputStream(privateKeyDest);
        OutputStream publicOut = new FileOutputStream(publicKeyDest);
        generateKeyPair(privateOut, publicOut, pass);

        assertTrue(new File(privateKeyDest).exists());
        assertTrue(new File(publicKeyDest).exists());
    }

    @Test
    void test_shouldCreateKeysAndImport() throws IOException, PGPException {
        String privateKeyDest = TEST_FOLDER + "/test_shouldCreateKeysAndImport.prv";
        String publicKeyDest = TEST_FOLDER + "/test_shouldCreateKeysAndImport.pub";

        OutputStream privateOut = new FileOutputStream(privateKeyDest);
        OutputStream publicOut = new FileOutputStream(publicKeyDest);
        generateKeyPair(privateOut, publicOut, pass);

        FileInputStream publicKeyInputStream = new FileInputStream(publicKeyDest);
        PGPPublicKey publicKeyRing = readPublicKey(publicKeyInputStream);
        assertTrue(publicKeyRing.isEncryptionKey());
        assertEquals(publicKeyRing.getBitStrength(), 1024);

        FileInputStream privateKeyInputStream = new FileInputStream(privateKeyDest);
        PGPSecretKey privateKeyRing = readSecretKey(privateKeyInputStream);
        assertEquals(privateKeyRing.getPublicKey().getBitStrength(), 1024);
        assertEquals(privateKeyRing.getEncoded().length, 681);
        
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