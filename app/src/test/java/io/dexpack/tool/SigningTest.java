package io.dexpack.tool;

import org.junit.Test;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.List;
import static org.junit.Assert.*;

public final class SigningTest {
    @Test public void defaultIdentityIsStable() throws Exception {
        assertEquals("04b8983c071fe50dafaeeb628c5975e5562d356ce1dae20f1e43fbc3870621c1",
                Signing.certificateDigest(Signing.defaultIdentity()));
    }

    @Test public void jksImportPreservesThePrivateKey() throws Exception {
        roundTrip("JKS", "store-pass".toCharArray(), "key-pass".toCharArray());
    }

    @Test public void pkcs12ImportPreservesThePrivateKey() throws Exception {
        roundTrip("PKCS12", "store-pass".toCharArray(), "store-pass".toCharArray());
    }

    @Test public void jksRejectsIncorrectPasswords() throws Exception {
        byte[] store = create("JKS", "store-pass".toCharArray(), "key-pass".toCharArray());
        assertThrows(Exception.class, () -> JksReader.read(store, "wrong".toCharArray(), "key-pass".toCharArray()));
        assertThrows(Exception.class, () -> JksReader.read(store, "store-pass".toCharArray(), "wrong".toCharArray()));
    }

    private static byte[] create(String type, char[] password, char[] keyPassword) throws Exception {
        Signing.Identity identity = Signing.defaultIdentity();
        KeyStore store = KeyStore.getInstance(type); store.load(null, password);
        store.setKeyEntry("test", identity.key, keyPassword, identity.chain.toArray(new Certificate[0]));
        ByteArrayOutputStream output = new ByteArrayOutputStream(); store.store(output, password); return output.toByteArray();
    }

    private static void roundTrip(String type, char[] password, char[] keyPassword) throws Exception {
        byte[] encoded = create(type, password, keyPassword);
        List<Signing.Identity> identities = type.equals("JKS")
                ? JksReader.read(encoded, password, keyPassword)
                : Signing.importStore(encoded, password, keyPassword);
        assertEquals(1, identities.size());
        Signing.Identity identity = identities.get(0);
        byte[] message = "native signing import".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA"); signer.initSign(identity.key); signer.update(message); byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withRSA"); verifier.initVerify(identity.chain.get(0)); verifier.update(message);
        assertTrue(verifier.verify(signature));
    }
}
