# PGPlug
A PGP plugin for Java project to make the use of PGP painless and easy.

![Test](https://github.com/no-such-company/PGPlug/workflows/Test/badge.svg?branch=main)![Java CI with Maven](https://github.com/no-such-company/PGPlug/workflows/Java%20CI%20with%20Maven/badge.svg)

This package uses Bouncycastel for PGP encryption.
Due to the high demands on PGP it is sometimes not possible to realize projects without high expertise.

Swen Kalski designed this package for the BlackChamber server and makes it universally usable for JAVA and Android projects with this repository.


## Basic usage

### create keys

Keys can be written directly to a file.

```java
String pass = "something123".toCharArray();

OutputStream privateOut = new FileOutputStream("test.prv");
OutputStream publicOut = new FileOutputStream("test.pub");

generateKeyPair(privateOut, publicOut, pass);

```

### read keys

```java

FileInputStream publicKeyInputStream = new FileInputStream("test.pub");
PGPPublicKey publicKeyRing = readPublicKey(publicKeyInputStream);

FileInputStream privateKeyInputStream = new FileInputStream("test.prv");
PGPSecretKey privateKeyRing = readSecretKey(privateKeyInputStream);
```

### encrytpData

Encrypt a plain Text with a set (or one) public key

The Encrypt method support plaintext with `char[]` as same as `inputStream()`

```java

public static byte[] encrypt(byte[] clearData, byte[]... publicKeys)

```

```java

public static void encrypt(
OutputStream out,
byte[] clearData,
Collection<PGPPublicKey> publicKeys
)
        
```

*Example:*

```java
final byte[] clearData = "1234567890".getBytes();

FileInputStream publicKeyInputStream = new FileInputStream("test.pub");
ByteArrayOutputStream encrypted_output = new ByteArrayOutputStream();

Set<PGPPublicKey> publicKeys = new HashSet<PGPPublicKey>();
publicKeys.add(readPublicKey(publicKeyInputStream));

PGPUtils.encrypt(encrypted_output, clearData, publicKeys);

// now you can save encryted_output
```

### decryptData

Decrypt data with the private key (secret).
`decrypt_outputstream` support OutputStream and `char[]`

```java

PGPUtils.decrypt(
        encryptedByteArray,
        readSecretKey(privateKeyInputStream),
        decrypt_outputStream, 
        pass);

```
