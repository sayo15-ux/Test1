package io.dexpack.tool;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.database.Cursor;
import android.net.Uri;

import java.io.StringReader;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * LSPosed/Xposed entry point. This is a runtime signature interceptor for
 * configured packages; it is deliberately separate from the static DEX
 * Signature Killer. It only replaces Java-layer PackageInfo results and does
 * not attempt native, file-read or self-integrity checks.
 */
public final class SignatureHook implements IXposedHookLoadPackage {
    private static final String PROVIDER = "content://" + HookConfig.AUTHORITY + "/config";
    private static volatile Set<String> targets = Collections.emptySet();
    private static volatile byte[] spoofCertificate;

    @Override public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam state) throws Throwable {
        XposedHelpers.findAndHookMethod("android.app.Application", state.classLoader, "attach",
                Context.class, new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        loadConfig((Context) param.args[0]);
                        if (targets.contains(state.packageName)) install(state);
                    }
                });
    }

    private static void loadConfig(Context context) {
        if (loadFromXposedPreferences()) return;
        if (context == null) return;
        try (Cursor cursor = context.getContentResolver().query(Uri.parse(PROVIDER), null, null, null, null)) {
            if (cursor == null || !cursor.moveToFirst()) return;
            int column = cursor.getColumnIndex("config");
            if (column < 0) return;
            Properties properties = new Properties();
            properties.load(new StringReader(cursor.getString(column)));
            applyConfig(properties.getProperty(HookConfig.KEY_TARGETS, ""),
                    properties.getProperty(HookConfig.KEY_CERTIFICATE, ""));
        } catch (Throwable ignored) {
            targets = Collections.emptySet();
            spoofCertificate = null;
        }
    }

    /** Preferred path: Xposed reads the module preference file directly. */
    private static boolean loadFromXposedPreferences() {
        try {
            XSharedPreferences preferences =
                    new XSharedPreferences(HookConfig.MODULE_PACKAGE, HookConfig.PREFS_NAME);
            preferences.makeWorldReadable();
            preferences.reload();
            if (!preferences.getFile().exists() || !preferences.getFile().canRead()) return false;
            applyConfig(preferences.getString(HookConfig.KEY_TARGETS, ""),
                    preferences.getString(HookConfig.KEY_CERTIFICATE, ""));
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void applyConfig(String targetValue, String certificateValue) {
        Set<String> next = new HashSet<>(HookConfig.split(targetValue));
        byte[] certificate = null;
        try {
            String encoded = certificateValue == null ? "" : certificateValue.trim();
            if (!encoded.isEmpty()) certificate = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException ignored) {
            certificate = null;
        }
        targets = Collections.unmodifiableSet(next);
        spoofCertificate = certificate;
    }

    private static XC_MethodHook replaceSignature(final XC_LoadPackage.LoadPackageParam state,
                                                   final boolean packageNameArgument) {
        return new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                int flags = flagsOf(param.args.length > 1 ? param.args[1] : null);
                int wanted = PackageManager.GET_SIGNATURES | PackageManager.GET_SIGNING_CERTIFICATES;
                if ((flags & wanted) == 0) return;
                if (packageNameArgument
                        && (param.args.length == 0 || !state.packageName.equals(String.valueOf(param.args[0])))) return;
                if (param.getResult() instanceof PackageInfo) {
                    apply((PackageInfo) param.getResult(), state.classLoader);
                }
            }
        };
    }

    private static void install(XC_LoadPackage.LoadPackageParam state) {
        try {
            Class<?> manager = XposedHelpers.findClass("android.app.ApplicationPackageManager", state.classLoader);
            XposedHelpers.findAndHookMethod(manager, "getPackageInfo", String.class, int.class, replaceSignature(state, true));
            XposedHelpers.findAndHookMethod(manager, "getPackageArchiveInfo", String.class, int.class, replaceSignature(state, false));
        } catch (Throwable ignored) {
            // The implementation class name differs on some ROMs; the remaining hooks still apply.
        }
        try {
            Class<?> flags = XposedHelpers.findClass("android.content.pm.PackageInfoFlags", state.classLoader);
            Class<?> manager = XposedHelpers.findClass("android.app.ApplicationPackageManager", state.classLoader);
            XposedHelpers.findAndHookMethod(manager, "getPackageInfo", String.class, flags, replaceSignature(state, true));
            XposedHelpers.findAndHookMethod(manager, "getPackageArchiveInfo", String.class, flags, replaceSignature(state, false));
            XposedHelpers.findAndHookMethod(manager, "getPackageInfoAsUser",
                    String.class, flags, int.class, replaceSignature(state, true));
        } catch (Throwable ignored) {
            // PackageInfoFlags overloads only exist on newer Android versions.
        }
        try {
            Class<?> manager = XposedHelpers.findClass("android.app.ApplicationPackageManager", state.classLoader);
            XposedHelpers.findAndHookMethod(manager, "getPackageInfoAsUser",
                    String.class, int.class, int.class, replaceSignature(state, true));
        } catch (Throwable ignored) {
            // Hidden overload is not present on every release.
        }
    }

    private static int flagsOf(Object value) {
        if (value instanceof Number) return ((Number) value).intValue();
        try {
            Object result = XposedHelpers.callMethod(value, "getValue");
            if (result instanceof Number) return ((Number) result).intValue();
        } catch (Throwable ignored) { }
        return 0;
    }

    @SuppressLint("NewApi")
    private static void apply(PackageInfo info, ClassLoader loader) {
        byte[] certificate = spoofCertificate;
        if (info == null || certificate == null) return;
        final Signature[] signatures;
        try {
            signatures = new Signature[]{new Signature(Arrays.copyOf(certificate, certificate.length))};
        } catch (Throwable ignored) {
            return;
        }
        info.signatures = signatures;
        try {
            Class<?> type = XposedHelpers.findClass("android.content.pm.SigningInfo", loader);
            Object value = XposedHelpers.newInstance(type, (Object) signatures);
            Field field = PackageInfo.class.getDeclaredField("signingInfo");
            field.setAccessible(true);
            field.set(info, value);
        } catch (Throwable ignored) {
            // Some platforms build SigningInfo differently; signatures are still replaced.
        }
    }
}
