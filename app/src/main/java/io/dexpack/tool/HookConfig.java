package io.dexpack.tool;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/** Persists the runtime-hook target list and spoof certificate. */
final class HookConfig {
    static final String MODULE_PACKAGE = "io.dexpack.tool";
    static final String AUTHORITY = MODULE_PACKAGE + ".hookconfig";
    static final String PREFS_NAME = "runtime_hook";
    static final String KEY_TARGETS = "targets";
    static final String KEY_CERTIFICATE = "certificate";

    private HookConfig() {}

    static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    static void write(Context context, Collection<String> targets, String certificateBase64) {
        SharedPreferences.Editor editor = preferences(context).edit();
        editor.putString(KEY_TARGETS, join(targets));
        editor.putString(KEY_CERTIFICATE, certificateBase64 == null ? "" : certificateBase64);
        if (!editor.commit()) throw new IllegalStateException("Cannot persist hook configuration.");
        // Xposed hook classes run in other app processes and read this file directly.
        File preferencesFile = new File(
                new File(context.getApplicationInfo().dataDir, "shared_prefs"), PREFS_NAME + ".xml");
        if (preferencesFile.isFile()) preferencesFile.setReadable(true, false);
    }

    static Properties read(Context context) {
        SharedPreferences preferences = preferences(context);
        Properties properties = new Properties();
        properties.setProperty(KEY_TARGETS, preferences.getString(KEY_TARGETS, ""));
        properties.setProperty(KEY_CERTIFICATE, preferences.getString(KEY_CERTIFICATE, ""));
        return properties;
    }

    static String format(Collection<String> targets, String certificateBase64) {
        Properties properties = new Properties();
        properties.setProperty(KEY_TARGETS, join(targets));
        properties.setProperty(KEY_CERTIFICATE, certificateBase64 == null ? "" : certificateBase64);
        StringWriter output = new StringWriter();
        try {
            properties.store(output, null);
        } catch (IOException error) {
            throw new IllegalStateException("Cannot write hook configuration.", error);
        }
        return output.toString();
    }

    static Properties parse(String text) {
        Properties properties = new Properties();
        try {
            if (text != null) properties.load(new StringReader(text));
        } catch (IOException error) {
            throw new IllegalArgumentException("Invalid hook configuration.", error);
        }
        return properties;
    }

    static String join(Collection<String> targets) {
        Set<String> unique = new LinkedHashSet<>();
        for (String value : targets) {
            if (value != null && !value.trim().isEmpty()) unique.add(value.trim());
        }
        return String.join("\n", unique);
    }

    static List<String> split(String value) {
        List<String> result = new ArrayList<>();
        if (value == null) return result;
        for (String part : value.split("[,\r\n\t ]+")) {
            if (!part.isEmpty()) result.add(part);
        }
        return Collections.unmodifiableList(result);
    }
}
