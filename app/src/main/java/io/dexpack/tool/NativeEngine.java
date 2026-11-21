package io.dexpack.tool;

import java.io.IOException;

public final class NativeEngine {
    static { System.loadLibrary("dexprotection"); }
    private NativeEngine() {}

    public interface Progress {
        void onProgress(String label, int percent);
    }

    public static native String[] inspect(String path) throws IOException;
    public static native String[] classes(String path) throws IOException;
    public static native long[] protect(String input, String output, int mode,
                                        String[] selected, Progress progress) throws IOException;
}
