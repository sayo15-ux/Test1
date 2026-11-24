package io.dexpack.tool;

import android.content.Context;
import android.content.SharedPreferences;

final class SignatureKillV4Config {
    static final String PREFS_NAME = "signature_kill_v4";

    private static final String KEY_PM_PROXY = "pm_proxy";
    private static final String KEY_PATCH_SIGNING_INFO = "patch_signing_info";
    private static final String KEY_REPLACE_APK_PATH = "replace_apk_path";
    private static final String KEY_PATCH_APPLICATION_INFO = "patch_application_info";
    private static final String KEY_EMBED_ORIGINAL_APK = "embed_original_apk";
    private static final String KEY_DELEGATE_ORIGINAL_APPLICATION = "delegate_original_application";
    private static final String KEY_DEBUGGABLE = "debuggable";
    private static final String KEY_CLEAN_ROOM = "clean_room";

    boolean pmProxy = true;
    boolean patchSigningInfo = true;
    boolean replaceApkPath;
    boolean patchApplicationInfo;
    boolean embedOriginalApk;
    boolean delegateOriginalApplication = true;
    boolean debuggable;
    boolean cleanRoom;

    static SignatureKillV4Config load(Context context) {
        SharedPreferences preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SignatureKillV4Config config = new SignatureKillV4Config();
        config.pmProxy = preferences.getBoolean(KEY_PM_PROXY, config.pmProxy);
        config.patchSigningInfo = preferences.getBoolean(KEY_PATCH_SIGNING_INFO, config.patchSigningInfo);
        config.replaceApkPath = preferences.getBoolean(KEY_REPLACE_APK_PATH, config.replaceApkPath);
        config.patchApplicationInfo = preferences.getBoolean(KEY_PATCH_APPLICATION_INFO, config.patchApplicationInfo);
        config.embedOriginalApk = preferences.getBoolean(KEY_EMBED_ORIGINAL_APK, config.embedOriginalApk);
        config.delegateOriginalApplication = preferences.getBoolean(KEY_DELEGATE_ORIGINAL_APPLICATION, config.delegateOriginalApplication);
        config.debuggable = preferences.getBoolean(KEY_DEBUGGABLE, config.debuggable);
        config.cleanRoom = preferences.getBoolean(KEY_CLEAN_ROOM, config.cleanRoom);
        return config;
    }

    void save(Context context) {
        SharedPreferences.Editor editor = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
        editor.putBoolean(KEY_PM_PROXY, pmProxy);
        editor.putBoolean(KEY_PATCH_SIGNING_INFO, patchSigningInfo);
        editor.putBoolean(KEY_REPLACE_APK_PATH, replaceApkPath);
        editor.putBoolean(KEY_PATCH_APPLICATION_INFO, patchApplicationInfo);
        editor.putBoolean(KEY_EMBED_ORIGINAL_APK, embedOriginalApk);
        editor.putBoolean(KEY_DELEGATE_ORIGINAL_APPLICATION, delegateOriginalApplication);
        editor.putBoolean(KEY_DEBUGGABLE, debuggable);
        editor.putBoolean(KEY_CLEAN_ROOM, cleanRoom);
        if (!editor.commit()) throw new IllegalStateException("Cannot save Signature Kill v4 configuration.");
    }

    int flags() {
        int flags = 0;
        if (pmProxy) flags |= 1;
        if (patchSigningInfo) flags |= 2;
        if (replaceApkPath) flags |= 4;
        if (patchApplicationInfo) flags |= 8;
        if (embedOriginalApk) flags |= 16;
        if (delegateOriginalApplication) flags |= 32;
        if (debuggable) flags |= 64;
        if (cleanRoom) flags |= 128;
        return flags;
    }
}
