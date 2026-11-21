package io.dexpack.tool;

import android.os.Build;
import android.os.Environment;

final class StorageAccess {
    static final String APP_ACCESS_ACTION = "android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION";
    static final String ACCESS_ACTION = "android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION";
    private StorageAccess() {}

    static boolean hasAllFiles() {
        if (Build.VERSION.SDK_INT < 30) return false;
        try {
            return Boolean.TRUE.equals(Environment.class.getMethod("isExternalStorageManager").invoke(null));
        } catch (ReflectiveOperationException error) { return false; }
    }
}
