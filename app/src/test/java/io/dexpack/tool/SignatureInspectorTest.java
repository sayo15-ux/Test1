package io.dexpack.tool;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Locale;

import static org.junit.Assert.*;

public final class SignatureInspectorTest {
    @Rule public final TemporaryFolder folder = new TemporaryFolder();

    private static String expectedFingerprint(X509Certificate certificate, String algorithm) throws Exception {
        byte[] digest = MessageDigest.getInstance(algorithm).digest(certificate.getEncoded());
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < digest.length; i++) {
            if (i > 0) text.append(':');
            text.append(String.format(Locale.ROOT, "%02X", digest[i] & 255));
        }
        return text.toString();
    }

    private static SignatureInspector.CertificateInfo certificate() throws Exception {
        return new SignatureInspector.CertificateInfo(Signing.defaultIdentity().chain.get(0));
    }

    @Test public void certificateInfoReportsRealFingerprints() throws Exception {
        X509Certificate source = Signing.defaultIdentity().chain.get(0);
        SignatureInspector.CertificateInfo info = new SignatureInspector.CertificateInfo(source);
        assertEquals(expectedFingerprint(source, "SHA-1"), info.sha1);
        assertEquals(expectedFingerprint(source, "SHA-256"), info.sha256);
        assertFalse(info.subject.isEmpty());
        assertFalse(info.serialNumber.isEmpty());
        assertTrue(info.publicKey.startsWith("RSA"));
    }

    @Test public void reportSeparatesIdentityFromIntegrity() throws Exception {
        SignatureInspector.Report valid = new SignatureInspector.Report(
                new File("signed.apk"), true, false, false, null,
                Collections.singletonList(new SignatureInspector.SchemeInfo("v2", true, true, 1)),
                Collections.singletonList(certificate()),
                Collections.emptyList(), Collections.emptyList(), false);
        String text = valid.text();
        assertTrue(text.contains("Valid signing configuration"));
        assertTrue(text.contains("v2: verified (1 signer(s))"));
        assertTrue(text.contains("SHA-256: " + expectedFingerprint(Signing.defaultIdentity().chain.get(0), "SHA-256")));
        assertTrue(text.contains("A certificate fingerprint identifies the signing key, not this specific file"));

        SignatureInspector.Report tampered = new SignatureInspector.Report(
                new File("signed.apk"), false, false, false, null,
                Collections.singletonList(new SignatureInspector.SchemeInfo("v2", true, false, 1)),
                Collections.singletonList(certificate()),
                Collections.singletonList("APK signature verification failed."),
                Collections.emptyList(), false);
        assertTrue(tampered.text().contains("Signature verification failed"));
        assertTrue(tampered.text().contains("present, NOT verified"));
        assertTrue(tampered.text().contains("* APK signature verification failed."));
    }

    @Test public void unsignedAndFailureReportsAreClear() throws Exception {
        SignatureInspector.Report unsigned = new SignatureInspector.Report(
                new File("unsigned.apk"), false, true, false, null,
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList(), false);
        assertEquals("No signature found", unsigned.status());
        assertTrue(unsigned.text().contains("appears unsigned"));

        File textFile = folder.newFile("text.apk");
        Files.write(textFile.toPath(), "not a zip".getBytes(StandardCharsets.UTF_8));
        SignatureInspector.Report malformed = SignatureInspector.inspect(textFile);
        assertFalse(malformed.inspected());
        assertTrue(malformed.malformed);
        assertEquals("Malformed APK", malformed.status());
        assertTrue(malformed.text().contains("Reason:"));

        File empty = folder.newFile("empty.apk");
        assertFalse(SignatureInspector.inspect(empty).inspected());
        assertFalse(SignatureInspector.inspect(new File(folder.getRoot(), "missing.apk")).inspected());
    }

    @Test public void realSampleApkIsInspectedWithoutGuessing() throws Exception {
        File sample = new File("../sample application.apk");
        Assume.assumeTrue("Sample APK is not available in this checkout", sample.isFile());
        SignatureInspector.Report report = SignatureInspector.inspect(sample);
        assertTrue("Inspection failed: " + report.failure, report.inspected());
        assertTrue(report.text().contains("- Signature schemes -"));
        assertTrue(report.text().contains("SHA-1: ") || report.unsigned);
    }

    @Test public void primaryCertificateEncodesAUsableReplacementIdentity() throws Exception {
        File sample = new File("../sample application.apk");
        Assume.assumeTrue("Sample APK is not available in this checkout", sample.isFile());
        SignatureInspector.CertificateSource source = SignatureInspector.primaryCertificate(sample);
        assertFalse(source.base64.isEmpty());
        assertFalse(source.subject.isEmpty());
        assertEquals(64, source.sha256.length());
        assertTrue(Base64.getDecoder().decode(source.base64).length > 0);
    }
}
