package io.dexpack.tool;

import android.app.Application;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;

import java.io.File;
import java.lang.ref.WeakReference;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
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
    final ArrayList<String> log = new ArrayList<>();

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

    void beginExecution(String command) {
        runOnMain(() -> {
            log.clear();
            appendLog("$ " + command);
            notifyState();
        });
    }

    void log(String message) {
        runOnMain(() -> {
            appendLog("  " + message);
            notifyState();
        });
    }

    void logError(String message) {
        runOnMain(() -> {
            appendLog("! " + message);
            notifyState();
        });
    }

    void step(String label, int progress) {
        runOnMain(() -> {
            status = label;
            percent = Math.max(0, Math.min(100, progress));
            appendLog("> " + label + " [" + percent + "%]");
            notifyState();
        });
    }

    private void runOnMain(Runnable action) {
        if (Looper.myLooper() == Looper.getMainLooper()) action.run();
        else main.post(action);
    }

    private void appendLog(String line) {
        String stamp = new SimpleDateFormat("HH:mm:ss", Locale.ROOT).format(new Date());
        log.add("[" + stamp + "] " + line);
        if (log.size() > 200) log.subList(0, log.size() - 200).clear();
    }

    Set<String> selection() { return mode == 1 ? v1Classes : v2Classes; }
    boolean ready() { return input != null && mode >= 0 && !busy && (mode == 0 || mode == 3 || mode == 4 || mode == 5 || mode == 6 || !selection().isEmpty()); }

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
        if (feature == 6) {
            modes[0] = false;
            modes[1] = true;
            modes[2] = true;
        }
        Signing.Identity chosen = signer;
        busy = true; processing = true; hasExecution = true; failed = false; saved = null; status = "Preparing…"; percent = 0;
        beginExecution("protect --mode " + feature + " --input " + source.label);
        ProcessService.start(this);
        worker.execute(() -> {
            File unsigned = null, signed = null;
            try {
                Signing.Identity identity = chosen != null ? chosen : Signing.defaultIdentity();
                if (source.metadata[1].startsWith("android.uid.") && chosen == null) {
                    throw new IllegalArgumentException("This system APK requires its original platform signing key.");
                }
                unsigned = File.createTempFile("job-", ".apk", getCacheDir());
                signed = File.createTempFile("job-", ".apk", getCacheDir());
                if (feature == 5) {
                    SignatureKillV3Config cfg = SignatureKillV3Config.load(this);
                    NativeEngine.setSignatureKillV3Options(cfg.flags(), cfg.fileRedirection);
                    log("sigkill-v3 flags=" + cfg.flags() + " redirection=" + cfg.fileRedirection + " version=" + cfg.version);
                }
                if (feature == 6) {
                    SignatureKillV4Config cfg = SignatureKillV4Config.load(this);
                    NativeEngine.setSignatureKillV4Options(cfg.flags());
                    log("sigkill-v4 flags=" + cfg.flags());
                }
                NativeEngine.protect(source.cached.getAbsolutePath(), unsigned.getAbsolutePath(), feature, classes,
                        (label, progress) -> updateProgress(label + "…", progress));
                updateProgress("Signing and verifying…", 85);
                if (feature == 6) Signing.signShared(unsigned, signed, identity, modes, source.minSdk());
                else Signing.sign(unsigned, signed, identity, modes, source.minSdk());
                updateProgress("Saving output…", 96);
                Storage.Saved result = Storage.publish(this, source, signed, feature);
                main.post(() -> { saved = result; percent = 100; busy = false; processing = false; status = "Output saved"; appendLog("+ output saved: " + result.path); notifyState(); ProcessService.stop(ProtectionApp.this); });
            } catch (Exception error) { fail(error); }
            finally {
                if (unsigned != null && unsigned.exists() && !unsigned.delete()) unsigned.deleteOnExit();
                if (signed != null && signed.exists() && !signed.delete()) signed.deleteOnExit();
            }
        });
    }

    private void updateProgress(String label, int progress) {
        if (Thread.currentThread().isInterrupted()) throw new java.util.concurrent.CancellationException("Processing cancelled.");
        main.post(() -> { status = label; percent = progress; appendLog("> " + label + " [" + progress + "%]"); notifyState(); notifyService(label, progress, true); });
    }

    private void notifyService(String text, int progress, boolean active) {
        try {
            android.app.NotificationManager nm = (android.app.NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            ProcessService.ensureChannel(this);
            android.content.Intent open = new android.content.Intent(this, MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP | android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP);
            android.app.PendingIntent pi = android.app.PendingIntent.getActivity(this, 1, open, android.app.PendingIntent.FLAG_UPDATE_CURRENT | (android.os.Build.VERSION.SDK_INT >= 23 ? android.app.PendingIntent.FLAG_IMMUTABLE : 0));
            android.app.Notification.Builder b = android.os.Build.VERSION.SDK_INT >= 26 ? new android.app.Notification.Builder(this, ProcessService.CHANNEL) : new android.app.Notification.Builder(this);
            b.setSmallIcon(android.R.drawable.stat_sys_download_done).setContentTitle("DexPack").setContentText(text).setContentIntent(pi).setOnlyAlertOnce(true).setOngoing(active);
            if (active) b.setProgress(100, Math.max(0, Math.min(100, progress)), progress <= 0); else b.setProgress(0,0,false);
            nm.notify(ProcessService.NOTIF_ID, b.build());
        } catch (Exception ignored) {}
    }

    private void fail(Exception error) {
        String message = error.getMessage();
        if (message == null || message.isEmpty()) message = error.getClass().getSimpleName();
        final String text = message;
        main.post(() -> { busy = false; processing = false; failed = true; status = text; appendLog("! " + text); notifyState(); notifyService("Failed: " + text, percent, false); ProcessService.stop(ProtectionApp.this); });
    }
}
