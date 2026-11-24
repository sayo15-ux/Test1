package io.dexpack.tool;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

public final class ProcessService extends Service {
    static final String CHANNEL = "process";
    static final int NOTIF_ID = 2101;
    static final String ACTION_STOP = "io.dexpack.tool.action.STOP";
    private boolean running;

    static void ensureChannel(Context c) {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL) != null) return;
        NotificationChannel ch = new NotificationChannel(CHANNEL, "Processing", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("APK protection progress");
        nm.createNotificationChannel(ch);
    }

    static void start(Context c) {
        ensureChannel(c);
        Intent i = new Intent(c, ProcessService.class);
        if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
    }

    static void stop(Context c) {
        c.stopService(new Intent(c, ProcessService.class));
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopForeground(true); stopSelf(); running = false; return START_NOT_STICKY;
        }
        ensureChannel(this);
        startForeground(NOTIF_ID, build("Starting…", 0, true));
        running = true;
        return START_NOT_STICKY;
    }

    void update(String text, int percent, boolean active) {
        if (!running) return;
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIF_ID, build(text, percent, active));
    }

    private Notification build(String text, int percent, boolean ongoing) {
        Intent open = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 1, open, PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0));
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        b.setSmallIcon(android.R.drawable.stat_sys_download_done)
         .setContentTitle("DexPack")
         .setContentText(text)
         .setContentIntent(pi)
         .setOnlyAlertOnce(true)
         .setOngoing(ongoing);
        if (ongoing) b.setProgress(100, Math.max(0, Math.min(100, percent)), percent <= 0);
        else b.setProgress(0, 0, false);
        return b.build();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
    @Override public void onDestroy() { running = false; super.onDestroy(); }
}
