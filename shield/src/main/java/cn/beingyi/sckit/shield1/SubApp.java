package cn.beingyi.sckit.shield1;

import android.app.Application;
import android.content.Context;
import android.os.Build;

public final class SubApp extends Application {
    static { System.loadLibrary("ScKitShieldV1"); }

    static native void attach(Context context);
    static native void create(Context application);
    static native void prepare(ClassLoader loader, String apk, String dataDirectory);
    static native void prepareFromRuntime(ClassLoader loader);

    static String originalApplication() { return "io.dexpack.template.OriginalApplication"; }
    static String originalFactory() { return "io.dexpack.template.OriginalFactory"; }

    @Override protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        if (Build.VERSION.SDK_INT < 28) attach(base);
    }

    @Override public void onCreate() {
        super.onCreate();
        if (Build.VERSION.SDK_INT < 28) create(this);
    }
}
