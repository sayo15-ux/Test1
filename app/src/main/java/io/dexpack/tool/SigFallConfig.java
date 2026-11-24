package io.dexpack.tool;

import android.content.Context;
import android.content.SharedPreferences;

final class SigFallConfig {
    static final int MODE_AUTOMATIC = 0;
    static final int MODE_STRENGTH = 1;
    static final int MODE_HIGH_STABILITY = 2;

    static final String PREFS_NAME = "sigfall";
    static final String[] VERSIONS = {"2.3.5", "2.3.4", "2.3.3", "2.3.2"};
    static final String[] REDIRECTIONS = {"default", "disabled", "sdcard", "files"};

    private static final String KEY_BASICS_TO_SIGN = "basics_to_sign";
    private static final String KEY_MODE = "mode";
    private static final String KEY_VERSION = "version";
    private static final String KEY_FILE_REDIRECTION = "file_redirection";
    private static final String KEY_RESOURCE_REDIRECTION = "resource_redirection";
    private static final String KEY_REPLACE_APK_PATH = "replace_apk_path";
    private static final String KEY_REPLACE_APP_CLASS_NAME = "replace_app_class_name";
    private static final String KEY_JAVA_HOOK_FRAMEWORK = "java_hook_framework";
    private static final String KEY_MAPS_HIDING = "maps_hiding";
    private static final String KEY_DEX_OBFUSCATION = "dex_obfuscation";
    private static final String KEY_DATA_REUSE_OPTIMIZATION = "data_reuse_optimization";
    private static final String KEY_DEBUGGABLE = "debuggable";
    private static final String KEY_DATA_FOLDER_NAME = "data_folder_name";
    private static final String KEY_LIBRARY_NAME = "library_name";

    boolean basicsToSign;
    int mode = MODE_AUTOMATIC;
    String version = VERSIONS[0];
    String fileRedirection = REDIRECTIONS[0];
    boolean resourceRedirection;
    boolean replaceApkPath;
    boolean replaceAppClassName;
    boolean javaHookFramework;
    boolean mapsHiding;
    boolean dexObfuscation;
    boolean dataReuseOptimization;
    boolean debuggable;
    String dataFolderName = "fancy";
    String libraryName = "fancy/lib/${arch}.so";

    static SigFallConfig load(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SigFallConfig config = new SigFallConfig();
        config.basicsToSign = preferences.getBoolean(KEY_BASICS_TO_SIGN, config.basicsToSign);
        config.mode = clamp(preferences.getInt(KEY_MODE, config.mode), 0, 2);
        config.version = allowed(preferences.getString(KEY_VERSION, config.version), VERSIONS, config.version);
        config.fileRedirection = allowed(preferences.getString(KEY_FILE_REDIRECTION, config.fileRedirection), REDIRECTIONS, config.fileRedirection);
        config.resourceRedirection = preferences.getBoolean(KEY_RESOURCE_REDIRECTION, config.resourceRedirection);
        config.replaceApkPath = preferences.getBoolean(KEY_REPLACE_APK_PATH, config.replaceApkPath);
        config.replaceAppClassName = preferences.getBoolean(KEY_REPLACE_APP_CLASS_NAME, config.replaceAppClassName);
        config.javaHookFramework = preferences.getBoolean(KEY_JAVA_HOOK_FRAMEWORK, config.javaHookFramework);
        config.mapsHiding = preferences.getBoolean(KEY_MAPS_HIDING, config.mapsHiding);
        config.dexObfuscation = preferences.getBoolean(KEY_DEX_OBFUSCATION, config.dexObfuscation);
        config.dataReuseOptimization = preferences.getBoolean(KEY_DATA_REUSE_OPTIMIZATION, config.dataReuseOptimization);
        config.debuggable = preferences.getBoolean(KEY_DEBUGGABLE, config.debuggable);
        config.dataFolderName = preferences.getString(KEY_DATA_FOLDER_NAME, config.dataFolderName);
        config.libraryName = preferences.getString(KEY_LIBRARY_NAME, config.libraryName);
        return config;
    }

    void save(Context context) {
        SharedPreferences.Editor editor = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        editor.putBoolean(KEY_BASICS_TO_SIGN, basicsToSign);
        editor.putInt(KEY_MODE, mode);
        editor.putString(KEY_VERSION, version);
        editor.putString(KEY_FILE_REDIRECTION, fileRedirection);
        editor.putBoolean(KEY_RESOURCE_REDIRECTION, resourceRedirection);
        editor.putBoolean(KEY_REPLACE_APK_PATH, replaceApkPath);
        editor.putBoolean(KEY_REPLACE_APP_CLASS_NAME, replaceAppClassName);
        editor.putBoolean(KEY_JAVA_HOOK_FRAMEWORK, javaHookFramework);
        editor.putBoolean(KEY_MAPS_HIDING, mapsHiding);
        editor.putBoolean(KEY_DEX_OBFUSCATION, dexObfuscation);
        editor.putBoolean(KEY_DATA_REUSE_OPTIMIZATION, dataReuseOptimization);
        editor.putBoolean(KEY_DEBUGGABLE, debuggable);
        editor.putString(KEY_DATA_FOLDER_NAME, dataFolderName);
        editor.putString(KEY_LIBRARY_NAME, libraryName);
        if (!editor.commit()) throw new IllegalStateException("Cannot save SigFall configuration.");
    }

    private static int clamp(int value, int minimum, int maximum) {
        return Math.max(minimum, Math.min(maximum, value));
    }

    private static String allowed(String value, String[] options, String fallback) {
        if (value == null) return fallback;
        for (String option : options) if (option.equals(value)) return value;
        return fallback;
    }
}
