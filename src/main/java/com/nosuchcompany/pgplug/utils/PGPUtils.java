package com.nosuchcompany.pgplug.utils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.*;
import java.util.*;

/*
    skalski created on 22/01/2021 inside the package - com.nosuchcompany.pgplug.utils
    Twitter: @KalskiSwen
*/

public class PGPUtils {

    private static KeyPairGenerator kpg;

    private static final boolean isArmored = true;

    private static final String identity = "identity";

    private static final boolean withIntegrityCheck = true;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final void generateKeyPair(OutputStream privateOut, OutputStream publicOut, char[] passPhrase){
        try {
            KeyPair pair = kpg.generateKeyPair();

            if (isArmored) {
                privateOut = new ArmoredOutputStream(privateOut);
            }

            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.YEAR, 5);

            PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, cal.getTime());
            PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION,
                    keyPair,
                    identity,
                    sha1Calc,
                    null,
                    null,
                    new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));

            secretKey.encode(privateOut);

            privateOut.close();

            if (isArmored) {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PGPPublicKey key = secretKey.getPublicKey();

            key.encode(publicOut);

            publicOut.close();
        } catch (PGPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static PGPPublicKey readPublicKey(byte[] data){
        return readPublicKey(new ByteArrayInputStream(data));
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(InputStream input){
        PGPPublicKeyRingCollection pgpPub = null;
        try {
            pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException  on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    /**
     * Search a secret key ring collection for a secret key corresponding to keyID if it
     * exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID  keyID we want.
     * @param passPhrase   passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] passPhrase)
            throws PGPException{
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase));
    }

    /**
     * decrypt the passPhraseed in message stream
     */
    public static void decrypt(byte[] encryptedData, byte[] key, OutputStream fOut, char[] passPhrase) {
        decrypt(new ByteArrayInputStream(encryptedData), new ByteArrayInputStream(key), fOut, passPhrase);
    }

    public static byte[] decrypt(InputStream encrypted, InputStream privateKeyIn, char[] passPhrase) throws IOException{
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        decrypt(encrypted, privateKeyIn, bOut, passPhrase);
        return bOut.toByteArray();
    }

    /**
     * decrypt the passed in message stream
     *
     * @param encrypted  The message to be decrypted.
     * @param privateKeyIn  private key InputStream.
     * @param fOut Clear text as a byte array.
     *
     * @return void
     * @exception IOException
     */
    public static void decrypt(
            InputStream encrypted,
            InputStream privateKeyIn,
            OutputStream fOut,
            char[] passPhrase)
            {

        try {
            encrypted = PGPUtil.getDecoderStream(encrypted);

            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(encrypted);
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();

                sKey = PGPUtils.findSecretKey(pgpSec, pbe.getKeyID(), passPhrase);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

            PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();

            InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);

            Object message = pgpFact.nextObject();

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();
                Streams.pipeAll(unc, fOut);
                fOut.close();
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                } else {
                    System.err.println("message integrity check passed");
                }
            } else {
                System.err.println("no message integrity check");
            }
        } catch (Exception e) {
            System.err.println(e);
        }
    }


    public static byte[] encrypt(byte[] clearData, byte[]... publicKeys) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        try {
            Set<PGPPublicKey> keys = new HashSet<PGPPublicKey>();
            for (byte[] publicKey : publicKeys) {
                keys.add(readPublicKey(publicKey));
            }
            encrypt(bOut, clearData, keys);
            return bOut.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Simple PGP encryptor between byte[].
     *
     * @param clearData  The data need to be encrypted
     * @param publicKeys Public Key Collection.  This method assumes that the
     *                   key is a public key
     * @param out        store encrypted data.
     *
     * @return void.
     * @exception IOException
     */
    public static void encrypt(
            OutputStream out,
            byte[] clearData,
            Collection<PGPPublicKey> publicKeys
            )
            {
        if (isArmored) {
            out = new ArmoredOutputStream(out);
        }

        try {
            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            for (PGPPublicKey publicKey : publicKeys) {
                cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));
            }

            OutputStream cOut = cPk.open(out, new byte[1 << 16]);

            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

            writeBytesToLiteralData(comData.open(cOut), PGPLiteralData.BINARY,"sealKey", clearData);

            comData.close();

            cOut.close();

            if (isArmored) {
                out.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void writeBytesToLiteralData(OutputStream out,
                                                char fileType,
                                                String name,
                                                byte[] bytes) throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, name,bytes.length, new Date());
        pOut.write(bytes);
    }
}
