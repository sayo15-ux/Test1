package io.dexpack.tool;

import android.app.Application;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;

import java.io.File;
import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ProtectionApp extends Application {
    interface Observer { void changed(); }
    final Handler main = new Handler(Looper.getMainLooper());
    final ExecutorService worker = Executors.newSingleThreadExecutor();
    private WeakReference<Observer> observer = new WeakReference<>(null);
    Storage.Input input;
    Storage.Saved saved;
    Signing.Identity signer;
    String[] allClasses;
    final Set<String> v1Classes = new HashSet<>(), v2Classes = new HashSet<>();
    final boolean[] schemes = {true, true, true};
    int mode = -1, percent;
    boolean busy, failed, processing, hasExecution;
    String status = "";

    @Override public void onCreate() {
        super.onCreate();
        File[] files = getCacheDir().listFiles();
        if (files != null) for (File file : files) {
            if (file.getName().matches("(?:input|job)-.*\\.(?:apk|part)") && !file.delete()) file.deleteOnExit();
        }
    }

    void observe(Observer value) { observer = new WeakReference<>(value); notifyState(); }
    void detach(Observer value) { if (observer.get() == value) observer.clear(); }
    void notifyState() { Observer value = observer.get(); if (value != null) value.changed(); }

    Set<String> selection() { return mode == 1 ? v1Classes : v2Classes; }
    boolean ready() { return input != null && mode >= 0 && !busy && (mode == 0 || mode == 3 || !selection().isEmpty()); }

    void select(Uri uri, File direct) {
        if (busy) return;
        if (input != null && !input.cached.delete()) input.cached.deleteOnExit();
        input = null; allClasses = null; hasExecution = false; v1Classes.clear(); v2Classes.clear();
        busy = true; failed = false; status = "Reading APK…"; percent = 0; saved = null; notifyState();
        worker.execute(() -> {
            try {
                Storage.Input next = Storage.importApk(this, uri, direct);
                main.post(() -> {
                    if (input != null && !input.cached.delete()) input.cached.deleteOnExit();
                    input = next; allClasses = null; v1Classes.clear(); v2Classes.clear();
                    busy = false; status = ""; notifyState();
                });
            } catch (Exception error) { fail(error); }
        });
    }

    void clear() {
        if (busy) return;
        if (input != null && !input.cached.delete()) input.cached.deleteOnExit();
        input = null; allClasses = null; saved = null; hasExecution = false;
        v1Classes.clear(); v2Classes.clear(); status = ""; failed = false; notifyState();
    }

    void loadClasses() {
        if (input == null || busy || allClasses != null) return;
        Storage.Input source = input;
        busy = true; failed = false; status = "Reading classes…"; percent = 0; notifyState();
        worker.execute(() -> {
            try {
                String[] names = NativeEngine.classes(source.cached.getAbsolutePath());
                main.post(() -> { allClasses = names; busy = false; status = ""; notifyState(); });
            } catch (Exception error) { fail(error); }
        });
    }

    void process() {
        if (!ready()) return;
        Storage.Input source = input;
        int feature = mode;
        String[] classes = selection().toArray(new String[0]);
        boolean[] modes = schemes.clone();
        Signing.Identity chosen = signer;
        busy = true; processing = true; hasExecution = true; failed = false; saved = null; status = "Preparing…"; percent = 0; notifyState();
        worker.execute(() -> {
            File unsigned = null, signed = null;
            try {
                Signing.Identity identity = chosen != null ? chosen : Signing.defaultIdentity();
                if (source.metadata[1].startsWith("android.uid.") && chosen == null) {
                    throw new IllegalArgumentException("This system APK requires its original platform signing key.");
                }
                unsigned = File.createTempFile("job-", ".apk", getCacheDir());
                signed = File.createTempFile("job-", ".apk", getCacheDir());
                NativeEngine.protect(source.cached.getAbsolutePath(), unsigned.getAbsolutePath(), feature, classes,
                        (label, progress) -> updateProgress(label + "…", progress));
                updateProgress("Signing and verifying…", 85);
                Signing.sign(unsigned, signed, identity, modes, source.minSdk());
                updateProgress("Saving output…", 96);
                Storage.Saved result = Storage.publish(this, source, signed, feature);
                main.post(() -> { saved = result; percent = 100; busy = false; processing = false; status = "Output saved"; notifyState(); });
            } catch (Exception error) { fail(error); }
            finally {
                if (unsigned != null && unsigned.exists() && !unsigned.delete()) unsigned.deleteOnExit();
                if (signed != null && signed.exists() && !signed.delete()) signed.deleteOnExit();
            }
        });
    }

    private void updateProgress(String label, int progress) {
        if (Thread.currentThread().isInterrupted()) throw new java.util.concurrent.CancellationException("Processing cancelled.");
        main.post(() -> { status = label; percent = progress; notifyState(); });
    }

    private void fail(Exception error) {
        String message = error.getMessage();
        if (message == null || message.isEmpty()) message = error.getClass().getSimpleName();
        final String text = message;
        main.post(() -> { busy = false; processing = false; failed = true; status = text; notifyState(); });
    }
}
