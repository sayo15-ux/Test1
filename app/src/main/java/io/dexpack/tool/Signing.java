package io.dexpack.tool;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

final class Signing {
    static final class Identity {
        final String name;
        final PrivateKey key;
        final List<X509Certificate> chain;

        Identity(String name, PrivateKey key, List<X509Certificate> chain) {
            this.name = name;
            this.key = key;
            this.chain = Collections.unmodifiableList(new ArrayList<>(chain));
        }

        String algorithm() { return key.getAlgorithm(); }
    }

    private Signing() {}

    static Identity defaultIdentity() throws Exception {
        byte[] pkcs8 = java.util.Base64.getDecoder().decode(BuiltInKey.PRIVATE_KEY);
        byte[] der = java.util.Base64.getDecoder().decode(BuiltInKey.CERTIFICATE);
        try {
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            return new Identity("Default", key, Collections.singletonList(certificate));
        } finally { Arrays.fill(pkcs8, (byte) 0); }
    }

    static List<Identity> importStore(byte[] bytes, char[] storePassword, char[] keyPassword) throws Exception {
        Exception last = null;
        for (String type : new String[]{"PKCS12", "JKS", "BKS"}) {
            try {
                KeyStore store = type.equals("BKS")
                        ? KeyStore.getInstance(type, new BouncyCastleProvider())
                        : type.equals("JKS") ? null : KeyStore.getInstance(type);
                if (store == null) return JksReader.read(bytes, storePassword, keyPassword);
                try (InputStream in = new ByteArrayInputStream(bytes)) { store.load(in, storePassword); }
                List<Identity> result = new ArrayList<>();
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (!store.isKeyEntry(alias)) continue;
                    Key key = store.getKey(alias, keyPassword.length == 0 ? storePassword : keyPassword);
                    if (!(key instanceof PrivateKey)) continue;
                    Certificate[] certificates = store.getCertificateChain(alias);
                    if (certificates == null || certificates.length == 0) continue;
                    List<X509Certificate> chain = new ArrayList<>();
                    for (Certificate c : certificates) {
                        if (!(c instanceof X509Certificate)) throw new IllegalArgumentException("Unsupported certificate.");
                        chain.add((X509Certificate) c);
                    }
                    result.add(new Identity(alias, (PrivateKey) key, chain));
                }
                if (result.isEmpty()) throw new IllegalArgumentException("Keystore contains no private signing key.");
                return result;
            } catch (Exception error) { last = error; }
        }
        throw new IllegalArgumentException("Cannot load key. Check the keystore and both passwords.", last);
    }

    static void sign(File input, File output, Identity identity, boolean[] schemes, int minSdk) throws Exception {
        if (schemes.length != 3 || !(schemes[0] || schemes[1] || schemes[2])) {
            throw new IllegalArgumentException("Select at least one signing mode.");
        }
        if (minSdk < 24 && !schemes[0]) {
            throw new IllegalArgumentException("This APK supports Android below 7.0; enable v1 signing.");
        }
        if (minSdk < 28 && !schemes[0] && !schemes[1]) {
            throw new IllegalArgumentException("This APK needs v1 or v2 signing for its minimum Android version.");
        }
        ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder("DEXPACK", identity.key, identity.chain).build();
        try {
            new ApkSigner.Builder(Collections.singletonList(config))
                    .setInputApk(input).setOutputApk(output).setMinSdkVersion(minSdk)
                    .setV1SigningEnabled(schemes[0]).setV2SigningEnabled(schemes[1])
                    .setV3SigningEnabled(schemes[2]).setV4SigningEnabled(false)
                    .setOtherSignersSignaturesPreserved(false).build().sign();
            int verificationMin = schemes[0] ? Math.min(minSdk, 23)
                    : schemes[1] ? Math.min(minSdk, 27) : minSdk;
            ApkVerifier.Result result = new ApkVerifier.Builder(output)
                    .setMinCheckedPlatformVersion(verificationMin).build().verify();
            if (!result.isVerified()) throw new IllegalStateException("Output signature verification failed: " + result.getErrors());
            if ((schemes[0] && !result.isVerifiedUsingV1Scheme())
                    || (schemes[1] && !result.isVerifiedUsingV2Scheme())
                    || (schemes[2] && !result.isVerifiedUsingV3Scheme())) {
                throw new IllegalStateException("A requested signature scheme is missing.");
            }
        } catch (Exception error) {
            if (output.exists() && !output.delete()) output.deleteOnExit();
            throw error;
        }
    }

    static String certificateDigest(Identity identity) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(identity.chain.get(0).getEncoded());
        StringBuilder s = new StringBuilder();
        for (byte b : digest) s.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return s.toString();
    }
}
