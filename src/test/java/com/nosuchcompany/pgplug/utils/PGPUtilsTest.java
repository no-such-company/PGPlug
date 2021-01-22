package com.nosuchcompany.pgplug.utils;

import com.nosuchcompany.pgplug.keyPair.KeyPairPGP;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.util.HashSet;
import java.util.Set;

class PGPUtilsTest {

    private static final byte[] clearData = "1234567890".getBytes();

    @Test
    void testHappyPath() {
        KeyPairPGP keyPair1 = new KeyPairPGP();
        KeyPairPGP keyPair2 = new KeyPairPGP();

        Set<PGPPublicKey> publicKeys = new HashSet<PGPPublicKey>();
        publicKeys.add(keyPair1.getPGPPublicKey());
        publicKeys.add(keyPair2.getPGPPublicKey());

        ByteArrayOutputStream enc_os = new ByteArrayOutputStream();
        PGPUtils.encrypt(enc_os, clearData, publicKeys);

        byte[] encryptedByteArray = enc_os.toByteArray();
        ByteArrayOutputStream dec_os = new ByteArrayOutputStream();
        PGPUtils.decrypt(encryptedByteArray, keyPair1.getPrivateKey(), dec_os);
        byte[] decryptedByteArray = dec_os.toByteArray();

        assertArrayEquals(clearData, decryptedByteArray);
        assertArrayEquals(clearData, dec_os.toByteArray());

        dec_os = new ByteArrayOutputStream();
        PGPUtils.decrypt(encryptedByteArray, keyPair2.getPrivateKey(), dec_os);
        decryptedByteArray = dec_os.toByteArray();
        assertArrayEquals(clearData, decryptedByteArray);
    }
}