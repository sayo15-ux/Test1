package io.dexpack.tool;

import android.content.Context;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 28)
public final class HookConfigTest {
    @Test public void targetsAndCertificateRoundTripThroughSharedPreferences() {
        Context context = RuntimeEnvironment.getApplication();
        HookConfig.write(context, Arrays.asList("com.example.a", "com.example.b", "com.example.a"), "QUJD");

        Properties stored = HookConfig.read(context);
        assertEquals("com.example.a\ncom.example.b",
                stored.getProperty(HookConfig.KEY_TARGETS));
        assertEquals("QUJD", stored.getProperty(HookConfig.KEY_CERTIFICATE));
        assertEquals(Arrays.asList("com.example.a", "com.example.b"),
                HookConfig.split(stored.getProperty(HookConfig.KEY_TARGETS)));
    }

    @Test public void serializedConfigurationIsParseable() {
        String serialized = HookConfig.format(Arrays.asList("com.example.one", "com.example.two"), "QUJD");
        Properties parsed = HookConfig.parse(serialized);

        assertEquals("com.example.one\ncom.example.two", parsed.getProperty(HookConfig.KEY_TARGETS));
        assertEquals("QUJD", parsed.getProperty(HookConfig.KEY_CERTIFICATE));

        List<String> targets = HookConfig.split(parsed.getProperty(HookConfig.KEY_TARGETS));
        assertEquals(2, targets.size());
        assertTrue(targets.contains("com.example.two"));
    }

    @Test public void splitAcceptsCommaSpaceAndNewlineSeparators() {
        assertEquals(Arrays.asList("a.b", "c.d", "e.f"),
                HookConfig.split("a.b, c.d\n e.f"));
    }
}
