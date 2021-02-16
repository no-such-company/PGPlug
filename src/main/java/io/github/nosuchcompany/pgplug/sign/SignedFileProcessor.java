package io.github.nosuchcompany.pgplug.sign;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Iterator;

import io.github.nosuchcompany.pgplug.utils.PGPUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

/*
    skalski created on 24/01/2021 inside the package - io.github.nosuchcompany.pgplug.utils
    Twitter: @KalskiSwen
*/

/**
 * A simple utility class that signs and verifies files.
 */
public class SignedFileProcessor {

    /**
     * Verify that the given file was signed by the owner of the pubKey
     *
     * @param in    The InputStream of the file that should be signed
     * @param keyIn The InputStream of the pubKey File
     * @throws Exception
     */
    public static boolean verifyFile(
            InputStream in,
            InputStream keyIn)
            throws Exception {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();
        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
        PGPOnePassSignature ops = p1.get(0);
        PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

        InputStream dIn = p2.getInputStream();
        int ch;
        PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
        PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
        FileOutputStream out = new FileOutputStream(p2.getFileName());
        try {
            ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

            while ((ch = dIn.read()) >= 0) {
                ops.update((byte) ch);
                out.write(ch);
            }
        } catch (Exception e) {
            return false;
        }

        out.close();
        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
        return ops.verify(p3.get(0));
    }


    /**
     * Verify that the given file was signed by the owner of the pubKey
     *
     * @param inStream    The InputStream of the file that should be signed
     * @param keyIn The InputStream of the pubKey File
     * @throws Exception
     * @return ByteArrayOutputStream
     */
    public static ByteArrayOutputStream verifyFile(
            ByteArrayInputStream inStream,
            InputStream keyIn)
            throws Exception {
        InputStream in = PGPUtil.getDecoderStream(inStream);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();
        pgpFact = new JcaPGPObjectFactory(c1.getDataStream());
        PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
        PGPOnePassSignature ops = p1.get(0);
        PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

        InputStream dIn = p2.getInputStream();
        int ch;
        PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
        PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

            while ((ch = dIn.read()) >= 0) {
                ops.update((byte) ch);
                out.write(ch);
            }
        } catch (Exception e) {
            return null;
        }

        PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
        if(ops.verify(p3.get(0))){
            return out;
        };

        return null;
    }

    /**
     * Generate an encapsulated signed file.
     *
     * @param fileName  the name of the file, that file that should be signed
     * @param keyIn the InputStream of the Secret Key that should sign the file
     * @param out the outputStream of the file that should be signed
     * @param pass the password wrt the secrect key
     * @param armor should be true if you have no idea what you are doing
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws PGPException
     * @throws SignatureException
     */
    public static void signFile(
            String fileName,
            InputStream keyIn,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        PGPSecretKey pgpSec = PGPUtils.readSecretKey(keyIn);
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        File file = new File(fileName);
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
        FileInputStream fIn = new FileInputStream(file);
        int ch;

        while ((ch = fIn.read()) >= 0) {
            lOut.write(ch);
            sGen.update((byte) ch);
        }

        lGen.close();
        sGen.generate().encode(bOut);
        cGen.close();
        if (armor) {
            out.close();
        }
    }

    /**
     * Generate an encapsulated signed file.
     *
     * @param fileName  the name of the file, that file that should be signed
     * @param pgpSec PrivateKeyRing
     * @param out the outputStream of the file that should be signed
     * @param pass the password wrt the secrect key
     * @param armor should be true if you have no idea what you are doing
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws PGPException
     * @throws SignatureException
     */
    public static void signFile(
            String fileName,
            PGPSecretKey pgpSec,
            OutputStream out,
            char[] pass,
            boolean armor)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();

            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator cGen = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        BCPGOutputStream bOut = new BCPGOutputStream(cGen.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        File file = new File(fileName);
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY, file);
        FileInputStream fIn = new FileInputStream(file);
        int ch;

        while ((ch = fIn.read()) >= 0) {
            lOut.write(ch);
            sGen.update((byte) ch);
        }

        lGen.close();
        sGen.generate().encode(bOut);
        cGen.close();
        if (armor) {
            out.close();
        }
    }


}