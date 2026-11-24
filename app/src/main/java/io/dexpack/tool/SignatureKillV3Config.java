package io.dexpack.tool;

import android.content.Context;
import android.content.SharedPreferences;

final class SignatureKillV3Config {
    static final String PREFS_NAME = "signature_kill_v3";
    static final String[] VERSIONS = {"3.0.0", "2.3.5", "2.3.4"};
    static final String[] REDIRECTIONS = {"default", "disabled", "files"};

    private static final String KEY_PM_PROXY = "pm_proxy";
    private static final String KEY_EARLY_PROVIDER = "early_provider";
    private static final String KEY_PATCH_SIGNING_INFO = "patch_signing_info";
    private static final String KEY_REPLACE_APK_PATH = "replace_apk_path";
    private static final String KEY_PATCH_APPLICATION_INFO = "patch_application_info";
    private static final String KEY_VERSION = "version";
    private static final String KEY_FILE_REDIRECTION = "file_redirection";
    private static final String KEY_BASICS_TO_SIGN = "basics_to_sign";
    private static final String KEY_DEBUGGABLE = "debuggable";

    boolean pmProxy = true;
    boolean earlyProvider = true;
    boolean patchSigningInfo = true;
    boolean replaceApkPath = true;
    boolean patchApplicationInfo = true;
    String version = VERSIONS[0];
    String fileRedirection = REDIRECTIONS[0];
    boolean basicsToSign;
    boolean debuggable;

    static SignatureKillV3Config load(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SignatureKillV3Config config = new SignatureKillV3Config();
        config.pmProxy = preferences.getBoolean(KEY_PM_PROXY, config.pmProxy);
        config.earlyProvider = preferences.getBoolean(KEY_EARLY_PROVIDER, config.earlyProvider);
        config.patchSigningInfo = preferences.getBoolean(KEY_PATCH_SIGNING_INFO, config.patchSigningInfo);
        config.replaceApkPath = preferences.getBoolean(KEY_REPLACE_APK_PATH, config.replaceApkPath);
        config.patchApplicationInfo = preferences.getBoolean(KEY_PATCH_APPLICATION_INFO, config.patchApplicationInfo);
        config.version = allowed(preferences.getString(KEY_VERSION, config.version), VERSIONS, config.version);
        config.fileRedirection = allowed(preferences.getString(KEY_FILE_REDIRECTION, config.fileRedirection), REDIRECTIONS, config.fileRedirection);
        config.basicsToSign = preferences.getBoolean(KEY_BASICS_TO_SIGN, config.basicsToSign);
        config.debuggable = preferences.getBoolean(KEY_DEBUGGABLE, config.debuggable);
        return config;
    }

    void save(Context context) {
        SharedPreferences.Editor editor = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        editor.putBoolean(KEY_PM_PROXY, pmProxy);
        editor.putBoolean(KEY_EARLY_PROVIDER, earlyProvider);
        editor.putBoolean(KEY_PATCH_SIGNING_INFO, patchSigningInfo);
        editor.putBoolean(KEY_REPLACE_APK_PATH, replaceApkPath);
        editor.putBoolean(KEY_PATCH_APPLICATION_INFO, patchApplicationInfo);
        editor.putString(KEY_VERSION, version);
        editor.putString(KEY_FILE_REDIRECTION, fileRedirection);
        editor.putBoolean(KEY_BASICS_TO_SIGN, basicsToSign);
        editor.putBoolean(KEY_DEBUGGABLE, debuggable);
        if (!editor.commit()) throw new IllegalStateException("Cannot save Signature Kill v3 configuration.");
    }

    int flags() {
        int flags = 0;
        if (pmProxy) flags |= 1;
        if (earlyProvider) flags |= 2;
        if (patchSigningInfo) flags |= 4;
        if (replaceApkPath) flags |= 8;
        if (patchApplicationInfo) flags |= 16;
        if (basicsToSign) flags |= 32;
        if (debuggable) flags |= 64;
        if ("files".equals(fileRedirection)) flags |= 128;
        return flags;
    }

    private static String allowed(String value, String[] options, String fallback) {
        if (value == null) return fallback;
        for (String option : options) if (option.equals(value)) return value;
        return fallback;
    }
}
