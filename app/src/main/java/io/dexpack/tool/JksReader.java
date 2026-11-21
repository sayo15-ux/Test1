package io.dexpack.tool;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.EncryptedPrivateKeyInfo;

final class JksReader {
    private JksReader() {}

    private static byte[] passwordBytes(char[] password) {
        byte[] bytes = new byte[password.length * 2];
        for (int i = 0; i < password.length; i++) {
            bytes[2 * i] = (byte) (password[i] >>> 8);
            bytes[2 * i + 1] = (byte) password[i];
        }
        return bytes;
    }

    static List<Signing.Identity> read(byte[] bytes, char[] storePassword, char[] keyPassword) throws Exception {
        if (bytes.length < 32) throw new IOException("Truncated JKS.");
        byte[] password = passwordBytes(storePassword);
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(password);
            sha.update("Mighty Aphrodite".getBytes(StandardCharsets.US_ASCII));
            sha.update(bytes, 0, bytes.length - 20);
            if (!MessageDigest.isEqual(sha.digest(), Arrays.copyOfRange(bytes, bytes.length - 20, bytes.length))) {
                throw new IOException("Incorrect JKS password or damaged keystore.");
            }
        } finally { Arrays.fill(password, (byte) 0); }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes, 0, bytes.length - 20));
        if (in.readInt() != 0xfeedfeed) throw new IOException("Not a JKS keystore.");
        int version = in.readInt(), count = in.readInt();
        if ((version != 1 && version != 2) || count < 0 || count > in.available() / 4) {
            throw new IOException("Invalid JKS header.");
        }
        List<Signing.Identity> result = new ArrayList<>();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < count; i++) {
            int tag = in.readInt();
            String alias = in.readUTF();
            in.readLong();
            if (tag == 1) {
                byte[] encrypted = block(in);
                int chainCount = in.readInt();
                if (chainCount <= 0 || chainCount > in.available() / 4) throw new IOException("Invalid JKS chain.");
                List<X509Certificate> chain = new ArrayList<>();
                for (int j = 0; j < chainCount; j++) chain.add(certificate(in, version, factory));
                byte[] plain = decrypt(encrypted, keyPassword.length == 0 ? storePassword : keyPassword);
                try {
                    PrivateKey key = KeyFactory.getInstance(chain.get(0).getPublicKey().getAlgorithm())
                            .generatePrivate(new PKCS8EncodedKeySpec(plain));
                    result.add(new Signing.Identity(alias, key, chain));
                } finally { Arrays.fill(plain, (byte) 0); }
            } else if (tag == 2) certificate(in, version, factory);
            else throw new IOException("Unknown JKS entry.");
        }
        if (in.available() != 0 || result.isEmpty()) throw new IOException("No private signing key in JKS.");
        return result;
    }

    private static byte[] block(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > in.available()) throw new IOException("Invalid JKS block length.");
        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }

    private static X509Certificate certificate(DataInputStream in, int version, CertificateFactory factory) throws Exception {
        if (version == 2 && !"X.509".equalsIgnoreCase(in.readUTF())) throw new IOException("Unsupported JKS certificate.");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(block(in)));
    }

    private static byte[] decrypt(byte[] encoded, char[] password) throws Exception {
        EncryptedPrivateKeyInfo info = new EncryptedPrivateKeyInfo(encoded);
        if (!"1.3.6.1.4.1.42.2.17.1.1".equals(info.getAlgName()) && !"JAVASOFT_JDKKeyProtector".equals(info.getAlgName())) {
            throw new IOException("Unsupported JKS private-key encryption.");
        }
        byte[] encrypted = info.getEncryptedData();
        if (encrypted.length <= 40) throw new IOException("Truncated encrypted JKS key.");
        byte[] pw = passwordBytes(password), plain = new byte[encrypted.length - 40];
        byte[] previous = Arrays.copyOf(encrypted, 20);
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            for (int at = 0; at < plain.length; at += 20) {
                sha.update(pw);
                previous = sha.digest(previous);
                for (int j = 0; j < 20 && at + j < plain.length; j++) {
                    plain[at + j] = (byte) (encrypted[20 + at + j] ^ previous[j]);
                }
            }
            sha.update(pw);
            if (!MessageDigest.isEqual(sha.digest(plain), Arrays.copyOfRange(encrypted, encrypted.length - 20, encrypted.length))) {
                throw new IOException("Incorrect JKS key password.");
            }
            return plain;
        } catch (Exception error) {
            Arrays.fill(plain, (byte) 0);
            throw error;
        } finally { Arrays.fill(pw, (byte) 0); Arrays.fill(previous, (byte) 0); }
    }
}
