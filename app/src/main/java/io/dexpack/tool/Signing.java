package io.dexpack.tool;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkSignerEngine;
import com.android.apksig.ApkVerifier;
import com.android.apksig.DefaultApkSignerEngine;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

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

    private static final class ZipRec {
        final String name;
        final byte[] central;
        final byte[] data;
        final long offset;
        ZipRec(String name, byte[] central, byte[] data, long offset) {
            this.name = name;
            this.central = central;
            this.data = data;
            this.offset = offset;
        }
    }

    private static long u32(byte[] b, int o) {
        return Integer.toUnsignedLong(ByteBuffer.wrap(b, o, 4).order(ByteOrder.LITTLE_ENDIAN).getInt(o));
    }

    private static byte[] localBytes(DataSource apk, ZipRec r) throws Exception {
        ByteBuffer h = apk.getByteBuffer(r.offset, 30).order(ByteOrder.LITTLE_ENDIAN);
        int name = Short.toUnsignedInt(h.getShort(26));
        int extra = Short.toUnsignedInt(h.getShort(28));
        int method = Short.toUnsignedInt(h.getShort(8));
        long data = r.offset + 30L + name + extra;
        int compressed = (int) u32(r.central, 20);
        byte[] packed = apk.getByteBuffer(data, compressed).array();
        if (method == 0) return packed;
        if (method != 8) throw new IllegalStateException("Unsupported ZIP method: " + method);
        Inflater inflater = new Inflater(true);
        inflater.setInput(packed);
        byte[] out = new byte[(int) u32(r.central, 24)];
        int off = 0;
        while (!inflater.finished() && off < out.length) {
            int n = inflater.inflate(out, off, out.length - off);
            if (n == 0) {
                if (inflater.needsInput() || inflater.needsDictionary()) break;
            }
            off += n;
        }
        inflater.end();
        if (off != out.length) throw new IllegalStateException("Unexpected entry size: " + r.name);
        return out;
    }

    private static byte[] androidManifest(DataSource apk, List<ZipRec> recs) throws Exception {
        for (ZipRec r : recs) {
            if (!r.name.equals("AndroidManifest.xml")) continue;
            return localBytes(apk, r);
        }
        throw new IllegalStateException("AndroidManifest.xml not found.");
    }

    private static boolean isV1SignatureEntry(String name) {
        if (!name.startsWith("META-INF/")) return false;
        String upper = name.toUpperCase(java.util.Locale.ROOT);
        return upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA")
                || upper.endsWith(".EC") || upper.equals("META-INF/MANIFEST.MF");
    }


    private static void writeLocal(ByteArrayOutputStream out, String name, byte[] data) throws Exception {
        ZipUtils.DeflateResult d = ZipUtils.deflate(ByteBuffer.wrap(data));
        LocalFileRecord.outputRecordWithDeflateCompressedData(name, 20, 0x800, d.output, d.inputCrc32,
                d.inputSizeBytes, new DataSink() {
                    @Override public void consume(byte[] b, int o, int l) { out.write(b, o, l); }
                    @Override public void consume(ByteBuffer b) {
                        byte[] x = new byte[b.remaining()];
                        b.get(x);
                        out.write(x, 0, x.length);
                    }
                });
    }

    private static void writeCentral(ByteArrayOutputStream out, String name, byte[] data, long offset) throws Exception {
        ZipUtils.DeflateResult d = ZipUtils.deflate(ByteBuffer.wrap(data));
        CentralDirectoryRecord r = CentralDirectoryRecord.createWithDeflateCompressedData(name, 20, 0x800,
                d.inputCrc32, d.output.length, d.inputSizeBytes, offset);
        ByteBuffer b = ByteBuffer.allocate(r.getSize());
        r.copyTo(b);
        out.write(b.array());
    }

    static void signShared(File input, File output, Identity identity, boolean[] schemes, int minSdk) throws Exception {
        if (schemes.length != 3 || !(schemes[0] || schemes[1] || schemes[2])) {
            throw new IllegalArgumentException("Select at least one signing mode.");
        }
        if (minSdk < 24 && !schemes[0]) {
            throw new IllegalArgumentException("This APK supports Android below 7.0; enable v1 signing.");
        }
        if (minSdk < 28 && !schemes[0] && !schemes[1]) {
            throw new IllegalArgumentException("This APK needs v1 or v2 signing for its minimum Android version.");
        }
        DefaultApkSignerEngine.SignerConfig config =
                new DefaultApkSignerEngine.SignerConfig.Builder("DEXPACK", identity.key, identity.chain).build();
        ApkSignerEngine engine = new DefaultApkSignerEngine.Builder(Collections.singletonList(config), minSdk)
                .setV1SigningEnabled(schemes[0]).setV2SigningEnabled(schemes[1])
                .setV3SigningEnabled(schemes[2]).setOtherSignersSignaturesPreserved(false).build();
        try {
            DataSource apk = DataSources.asDataSource(new RandomAccessFile(input, "r"));
            ApkUtils.ZipSections sections = ApkUtils.findZipSections(apk);
            ByteBuffer central = apk.getByteBuffer(sections.getZipCentralDirectoryOffset(),
                    (int) sections.getZipCentralDirectorySizeBytes()).order(ByteOrder.LITTLE_ENDIAN);
            List<ZipRec> recs = new ArrayList<>();
            Set<String> names = new HashSet<>();
            while (central.remaining() >= 46) {
                int start = central.position();
                int nameLen = Short.toUnsignedInt(central.getShort(start + 28));
                int extraLen = Short.toUnsignedInt(central.getShort(start + 30));
                int commentLen = Short.toUnsignedInt(central.getShort(start + 32));
                int size = 46 + nameLen + extraLen + commentLen;
                byte[] raw = new byte[size];
                central.position(start);
                central.get(raw);
                String name = new String(raw, 46, nameLen, StandardCharsets.UTF_8);
                if (!name.endsWith("/")) {
                    recs.add(new ZipRec(name, raw, null, u32(raw, 42)));
                    names.add(name);
                }
                central.position(start + size);
            }
            recs.sort((a, b) -> Long.compare(a.offset, b.offset));
            Set<String> skip = engine.initWith(androidManifest(apk, recs), names);
            for (ZipRec r : recs) {
                ApkSignerEngine.InputJarEntryInstructions instructions = engine.inputJarEntry(r.name);
                byte[] bytes = localBytes(apk, r);
                ApkSignerEngine.InspectJarEntryRequest inspect = instructions.getInspectJarEntryRequest();
                if (inspect != null) {
                    inspect.getDataSink().consume(ByteBuffer.wrap(bytes));
                    inspect.done();
                }
                ApkSignerEngine.InspectJarEntryRequest produced = engine.outputJarEntry(r.name);
                if (produced != null) {
                    produced.getDataSink().consume(ByteBuffer.wrap(bytes));
                    produced.done();
                }
            }
            long cdStart = sections.getZipCentralDirectoryOffset();
            try (FileOutputStream out = new FileOutputStream(output)) {
                byte[] buffer = new byte[1024 * 1024];
                try (InputStream in = input.toPath().toUri().toURL().openStream()) {
                    long left = cdStart;
                    while (left > 0) {
                        int n = in.read(buffer, 0, (int) Math.min(buffer.length, left));
                        if (n < 0) throw new IllegalStateException("Unexpected end of APK.");
                        out.write(buffer, 0, n);
                        left -= n;
                    }
                }
                List<ZipRec> added = new ArrayList<>();
                ApkSignerEngine.OutputJarSignatureRequest signatures = engine.outputJarEntries();
                if (signatures != null) {
                    for (ApkSignerEngine.OutputJarSignatureRequest.JarEntry entry : signatures.getAdditionalJarEntries()) {
                        long offset = cdStart;
                        ByteArrayOutputStream local = new ByteArrayOutputStream();
                        writeLocal(local, entry.getName(), entry.getData());
                        byte[] bytes = local.toByteArray();
                        out.write(bytes);
                        cdStart += bytes.length;
                        added.add(new ZipRec(entry.getName(), null, entry.getData(), offset));
                        ApkSignerEngine.InspectJarEntryRequest inspect = engine.outputJarEntry(entry.getName());
                        if (inspect != null) {
                            inspect.getDataSink().consume(ByteBuffer.wrap(entry.getData()));
                            inspect.done();
                        }
                    }
                    signatures.done();
                }
                Set<String> addedNames = new HashSet<>();
                for (ZipRec r : added) addedNames.add(r.name);
                boolean hasManifest = false;
                int cdCount = 0;
                ByteArrayOutputStream directory = new ByteArrayOutputStream();
                for (ZipRec r : recs) {
                    if (addedNames.contains(r.name)) continue;
                    if (schemes[0] && isV1SignatureEntry(r.name)) continue;
                    directory.write(r.central);
                    cdCount++;
                    if (r.name.equals("AndroidManifest.xml")) hasManifest = true;
                }
                for (ZipRec r : added) {
                    writeCentral(directory, r.name, r.data, r.offset);
                    cdCount++;
                    if (r.name.equals("AndroidManifest.xml")) hasManifest = true;
                }
                if (!hasManifest) {
                    throw new IllegalStateException("Missing AndroidManifest.xml; skip=" + skip);
                }
                byte[] directoryBytes = directory.toByteArray();
                int padding = (int) ((4096 - (cdStart % 4096)) % 4096);
                long blockOffset = cdStart + padding;
                ByteBuffer digestEocd = eocd(cdCount, directoryBytes.length, blockOffset);
                DataSource prefix = DataSources.asDataSource(new RandomAccessFile(output, "r"), 0, cdStart);
                ApkSignerEngine.OutputApkSigningBlockRequest2 request = engine.outputZipSections2(
                        padding == 0 ? prefix : new com.android.apksig.internal.util.ChainedDataSource(prefix,
                                DataSources.asDataSource(ByteBuffer.allocate(padding))),
                        DataSources.asDataSource(ByteBuffer.wrap(directoryBytes)),
                        DataSources.asDataSource(digestEocd));
                if (padding > 0) out.write(new byte[padding]);
                if (request != null) {
                    out.write(request.getApkSigningBlock());
                    request.done();
                }
                long directoryOffset = cdStart + padding + (request == null ? 0 : request.getApkSigningBlock().length);
                out.write(directoryBytes);
                out.write(eocd(cdCount, directoryBytes.length, directoryOffset).array());
                engine.outputDone();
            }
        } finally {
            engine.close();
        }
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
    }

    private static ByteBuffer eocd(int count, int directorySize, long directoryOffset) {
        ByteBuffer b = ByteBuffer.allocate(22).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0x06054b50).putShort((short) 0).putShort((short) 0).putShort((short) count).putShort((short) count);
        b.putInt(directorySize).putInt((int) directoryOffset).putShort((short) 0);
        b.flip();
        return b;
    }

    static String certificateDigest(Identity identity) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(identity.chain.get(0).getEncoded());
        StringBuilder s = new StringBuilder();
        for (byte b : digest) s.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return s.toString();
    }
}
