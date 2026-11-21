package io.dexpack.tool;

import com.android.apksig.ApkVerifier;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Reads an APK's signing information with the apksig library already used by
 * {@link Signing}. This class only reports what apksig actually verified; it
 * never guesses a signing scheme or a certificate from file names.
 */
final class SignatureInspector {
    private SignatureInspector() {}

    static final class CertificateInfo {
        final String subject, issuer, serialNumber, validFrom, validUntil;
        final String publicKey;
        final String sha1, sha256, base64;

        CertificateInfo(X509Certificate certificate) {
            subject = certificate.getSubjectX500Principal().getName();
            issuer = certificate.getIssuerX500Principal().getName();
            serialNumber = certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT);
            DateFormat dates = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM, Locale.ROOT);
            validFrom = dates.format(certificate.getNotBefore());
            validUntil = dates.format(certificate.getNotAfter());
            PublicKey key = certificate.getPublicKey();
            publicKey = key.getAlgorithm()
                    + (key instanceof RSAPublicKey
                        ? " (" + ((RSAPublicKey) key).getModulus().bitLength() + " bits)" : "");
            sha1 = fingerprint(certificate, "SHA-1");
            sha256 = fingerprint(certificate, "SHA-256");
            base64 = encode(certificate);
        }

        private static String encode(X509Certificate certificate) {
            try {
                return Base64.getEncoder().encodeToString(certificate.getEncoded());
            } catch (Exception error) {
                return "";
            }
        }

        private static String fingerprint(X509Certificate certificate, String algorithm) {
            try {
                byte[] digest = MessageDigest.getInstance(algorithm).digest(certificate.getEncoded());
                StringBuilder text = new StringBuilder();
                for (int i = 0; i < digest.length; i++) {
                    if (i > 0) text.append(':');
                    text.append(String.format(Locale.ROOT, "%02X", digest[i] & 255));
                }
                return text.toString();
            } catch (Exception error) {
                return "Unavailable";
            }
        }
    }

    /** The certificate selected as the replacement identity for runtime hooking. */
    static final class CertificateSource {
        final String base64, sha256, subject;

        CertificateSource(String base64, String sha256, String subject) {
            this.base64 = base64;
            this.sha256 = sha256;
            this.subject = subject;
        }
    }

    static final class SchemeInfo {
        final String name;
        final boolean present, verified;
        final int signers;

        SchemeInfo(String name, boolean present, boolean verified, int signers) {
            this.name = name;
            this.present = present;
            this.verified = verified;
            this.signers = signers;
        }
    }

    static final class Report {
        final File file;
        final boolean valid, unsigned, malformed;
        final String failure;
        final List<SchemeInfo> schemes;
        final List<CertificateInfo> certificates;
        final List<String> errors, warnings;
        final boolean sourceStampVerified;

        Report(File file, boolean valid, boolean unsigned, boolean malformed, String failure,
               List<SchemeInfo> schemes, List<CertificateInfo> certificates,
               List<String> errors, List<String> warnings, boolean sourceStampVerified) {
            this.file = file;
            this.valid = valid;
            this.unsigned = unsigned;
            this.malformed = malformed;
            this.failure = failure;
            this.schemes = Collections.unmodifiableList(new ArrayList<>(schemes));
            this.certificates = Collections.unmodifiableList(new ArrayList<>(certificates));
            this.errors = Collections.unmodifiableList(new ArrayList<>(errors));
            this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
            this.sourceStampVerified = sourceStampVerified;
        }

        boolean inspected() { return failure == null; }

        String status() {
            if (!inspected()) return malformed ? "Malformed APK" : "Could not inspect APK";
            if (unsigned) return "No signature found";
            return valid ? "Valid signing configuration" : "Signature verification failed";
        }

        String text() {
            StringBuilder text = new StringBuilder();
            text.append("APK: ").append(file == null ? "unknown" : file.getName()).append('\n');
            if (file != null) text.append("Size: ").append(file.length()).append(" bytes\n");
            text.append('\n');
            if (!inspected()) {
                text.append("Result: ").append(status()).append('\n');
                text.append("Reason: ").append(failure).append('\n');
                return text.toString();
            }
            text.append("Result: ").append(status()).append('\n');
            if (unsigned) {
                text.append("No signing identity was found in this APK. It appears unsigned or its "
                        + "signatures were removed; Android will not install it as a normal app.\n\n");
            } else if (valid) {
                text.append("The signatures verify on the checked Android platform range. "
                        + "This covers APK installation verification by the platform.\n\n");
            } else {
                text.append("At least one signature scheme did not verify. The APK may have been "
                        + "changed after signing, be damaged, or use an unsupported configuration.\n\n");
            }
            text.append("- Signature schemes -\n");
            for (SchemeInfo scheme : schemes) {
                text.append(scheme.name).append(": ")
                        .append(scheme.verified ? "verified"
                                : scheme.present ? "present, NOT verified" : "not present")
                        .append(" (").append(scheme.signers).append(" signer(s))\n");
                if (scheme.name.equals("v4 (.idsig)") && !scheme.present) {
                    text.append("  v4 needs a sibling .idsig sidecar file; none was found.\n");
                }
            }
            text.append('\n');
            text.append("- Certificate identity -\n");
            if (certificates.isEmpty()) {
                text.append("No certificate could be read.\n\n");
            } else {
                for (int i = 0; i < certificates.size(); i++) {
                    CertificateInfo certificate = certificates.get(i);
                    text.append("Signer ").append(i + 1).append('\n');
                    text.append("  Subject: ").append(certificate.subject).append('\n');
                    text.append("  Issuer: ").append(certificate.issuer).append('\n');
                    text.append("  Serial: ").append(certificate.serialNumber).append('\n');
                    text.append("  Valid: ").append(certificate.validFrom)
                            .append(" to ").append(certificate.validUntil).append('\n');
                    text.append("  Public key: ").append(certificate.publicKey).append('\n');
                    text.append("  SHA-1: ").append(certificate.sha1).append('\n');
                    text.append("  SHA-256: ").append(certificate.sha256).append('\n');
                }
                text.append('\n');
            }
            text.append("- Important -\n");
            text.append("A certificate fingerprint identifies the signing key, not this specific "
                    + "file. The same key produces the same fingerprint for every build. APK "
                    + "integrity is proven only by the verification result above, not by the "
                    + "certificate.\n\n");
            text.append("Source stamp: ")
                    .append(sourceStampVerified ? "verified" : "not verified or absent").append('\n');
            if (!errors.isEmpty()) {
                text.append("\n- Verification errors -\n");
                for (String error : errors) text.append("* ").append(error).append('\n');
            }
            if (!warnings.isEmpty()) {
                text.append("\n- Warnings -\n");
                for (String warning : warnings) text.append("* ").append(warning).append('\n');
            }
            return text.toString();
        }
    }

    /**
     * Extracts the first certificate encoded in an APK so the runtime hook can
     * return it to apps that ask for the target's signature.
     */
    static CertificateSource primaryCertificate(File apk) throws IOException {
        Report report = inspect(apk);
        if (!report.inspected()) throw new IOException(report.failure == null ? "Cannot read APK." : report.failure);
        if (report.certificates.isEmpty()) throw new IOException("The APK has no certificate to use.");
        CertificateInfo certificate = report.certificates.get(0);
        if (certificate.base64.isEmpty()) throw new IOException("The certificate cannot be encoded.");
        return new CertificateSource(certificate.base64, certificate.sha256, certificate.subject);
    }

    static Report inspect(File apk) {
        if (apk == null) return failure(null, "No APK was provided.", false);
        if (!apk.exists() || !apk.isFile()) return failure(apk, "The APK file does not exist.", false);
        if (!apk.canRead()) return failure(apk, "The APK file cannot be read.", false);
        if (apk.length() == 0) return failure(apk, "The APK file is empty.", false);
        try {
            File v4Signature = new File(apk.getAbsolutePath() + ".idsig");
            ApkVerifier.Builder builder = new ApkVerifier.Builder(apk);
            if (v4Signature.isFile() && v4Signature.canRead()) builder.setV4SignatureFile(v4Signature);
            ApkVerifier.Result result = builder.build().verify();
            List<ApkVerifier.Result.V1SchemeSignerInfo> v1 = result.getV1SchemeSigners();
            List<ApkVerifier.Result.V1SchemeSignerInfo> v1Ignored = result.getV1SchemeIgnoredSigners();
            List<ApkVerifier.Result.V2SchemeSignerInfo> v2 = result.getV2SchemeSigners();
            List<ApkVerifier.Result.V3SchemeSignerInfo> v3 = result.getV3SchemeSigners();
            List<ApkVerifier.Result.V3SchemeSignerInfo> v31 = result.getV31SchemeSigners();
            List<ApkVerifier.Result.V4SchemeSignerInfo> v4 = result.getV4SchemeSigners();
            boolean hasSigners = !v1.isEmpty() || !v1Ignored.isEmpty() || !v2.isEmpty()
                    || !v3.isEmpty() || !v31.isEmpty() || !v4.isEmpty();

            List<String> errors = new ArrayList<>();
            boolean noSignatureIssue = false;
            for (ApkVerifier.IssueWithParams issue : result.getAllErrors()) {
                errors.add(issue.toString());
                ApkVerifier.Issue kind = issue.getIssue();
                if (kind == ApkVerifier.Issue.JAR_SIG_NO_SIGNATURES
                        || kind == ApkVerifier.Issue.V2_SIG_NO_SIGNATURES
                        || kind == ApkVerifier.Issue.V3_SIG_NO_SIGNATURES) noSignatureIssue = true;
            }
            boolean unsigned = !result.isVerified() && !hasSigners && noSignatureIssue;

            List<SchemeInfo> schemes = new ArrayList<>();
            schemes.add(new SchemeInfo("v1 (JAR signing)", !v1.isEmpty() || !v1Ignored.isEmpty(),
                    result.isVerifiedUsingV1Scheme(), v1.size() + v1Ignored.size()));
            schemes.add(new SchemeInfo("v2", !v2.isEmpty(), result.isVerifiedUsingV2Scheme(), v2.size()));
            schemes.add(new SchemeInfo("v3", !v3.isEmpty(), result.isVerifiedUsingV3Scheme(), v3.size()));
            schemes.add(new SchemeInfo("v3.1", !v31.isEmpty(), result.isVerifiedUsingV31Scheme(), v31.size()));
            schemes.add(new SchemeInfo("v4 (.idsig)", !v4.isEmpty(), result.isVerifiedUsingV4Scheme(), v4.size()));

            List<String> warnings = new ArrayList<>();
            for (ApkVerifier.IssueWithParams issue : result.getWarnings()) warnings.add(issue.toString());

            return new Report(apk, result.isVerified(), unsigned, false, null, schemes,
                    certificates(result), errors, warnings, result.isSourceStampVerified());
        } catch (com.android.apksig.apk.ApkFormatException error) {
            return failure(apk, "Malformed APK: " + message(error), true);
        } catch (Exception error) {
            return failure(apk, message(error), false);
        }
    }

    private static List<CertificateInfo> certificates(ApkVerifier.Result result) {
        List<X509Certificate> found = new ArrayList<>(result.getSignerCertificates());
        for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) add(found, signer.getCertificate());
        for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeIgnoredSigners()) add(found, signer.getCertificate());
        for (ApkVerifier.Result.V2SchemeSignerInfo signer : result.getV2SchemeSigners()) add(found, signer.getCertificate());
        for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV3SchemeSigners()) add(found, signer.getCertificate());
        for (ApkVerifier.Result.V3SchemeSignerInfo signer : result.getV31SchemeSigners()) add(found, signer.getCertificate());
        for (ApkVerifier.Result.V4SchemeSignerInfo signer : result.getV4SchemeSigners()) add(found, signer.getCertificate());
        List<CertificateInfo> certificates = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (X509Certificate certificate : found) {
            String fingerprint;
            try {
                fingerprint = hex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
            } catch (Exception ignored) {
                fingerprint = certificate.toString();
            }
            if (seen.add(fingerprint)) certificates.add(new CertificateInfo(certificate));
        }
        return certificates;
    }

    private static void add(List<X509Certificate> target, X509Certificate certificate) {
        if (certificate != null) target.add(certificate);
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte value : bytes) text.append(String.format(Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }

    private static Report failure(File apk, String reason, boolean malformed) {
        return new Report(apk, false, false, malformed, reason, Collections.emptyList(),
                Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), false);
    }

    private static String message(Exception error) {
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }
}
