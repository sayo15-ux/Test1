package io.dexpack.tool;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.UUID;

final class Storage {
    static final class Input {
        final File cached, original;
        final String name, label, location;
        final String[] metadata;
        final Drawable icon;

        Input(File cached, File original, String name, String label, String location, String[] metadata, Drawable icon) {
            this.cached = cached; this.original = original; this.name = name;
            this.label = label; this.location = location; this.metadata = metadata; this.icon = icon;
        }
        int minSdk() { return Integer.parseInt(metadata[2]); }
    }

    static final class Saved {
        final Uri uri;
        final String path;
        final boolean besideInput;
        Saved(Uri uri, String path, boolean besideInput) { this.uri = uri; this.path = path; this.besideInput = besideInput; }
    }

    private Storage() {}

    static Input importApk(Context context, Uri uri, File directFile) throws Exception {
        ContentResolver resolver = context.getContentResolver();
        String name = directFile != null ? directFile.getName() : displayName(resolver, uri);
        File original = directFile != null ? directFile.getCanonicalFile() : resolveFile(context, uri);
        File cached = File.createTempFile("input-", ".apk", context.getCacheDir());
        try {
            try (InputStream in = directFile != null ? new FileInputStream(directFile) : resolver.openInputStream(uri);
                 FileOutputStream out = new FileOutputStream(cached)) {
                if (in == null) throw new IOException("Cannot open this APK.");
                copy(in, out);
                out.getFD().sync();
            }
            String[] metadata = NativeEngine.inspect(cached.getAbsolutePath());
            PackageInfo info = context.getPackageManager().getPackageArchiveInfo(cached.getAbsolutePath(), 0);
            String label = metadata[0];
            Drawable icon = null;
            if (info != null && info.applicationInfo != null) {
                ApplicationInfo app = info.applicationInfo;
                app.sourceDir = cached.getAbsolutePath();
                app.publicSourceDir = cached.getAbsolutePath();
                label = context.getPackageManager().getApplicationLabel(app).toString();
                icon = context.getPackageManager().getApplicationIcon(app);
            }
            String location = original != null ? original.getAbsolutePath() : name;
            return new Input(cached, original, name, label, location, metadata, icon);
        } catch (Exception error) {
            if (!cached.delete()) cached.deleteOnExit();
            throw error;
        }
    }

    static String displayName(ContentResolver resolver, Uri uri) {
        try (Cursor cursor = resolver.query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                String name = cursor.getString(0);
                if (name != null && !name.isEmpty()) return name;
            }
        } catch (RuntimeException ignored) { }
        return "application.apk";
    }

    static File resolveFile(Context context, Uri uri) {
        if (uri == null) return null;
        try {
            if ("file".equals(uri.getScheme())) return new File(uri.getPath()).getCanonicalFile();
            if (DocumentsContract.isDocumentUri(context, uri)) {
                String id = DocumentsContract.getDocumentId(uri);
                if ("com.android.externalstorage.documents".equals(uri.getAuthority())) {
                    String[] parts = id.split(":", 2);
                    if (parts.length == 2) {
                        File root = "primary".equalsIgnoreCase(parts[0]) ? Environment.getExternalStorageDirectory() : new File("/storage", parts[0]);
                        File candidate = new File(root, parts[1]).getCanonicalFile();
                        String prefix = root.getCanonicalPath() + File.separator;
                        if (candidate.getPath().startsWith(prefix) && candidate.isFile()) return candidate;
                    }
                }
                if ("com.android.providers.downloads.documents".equals(uri.getAuthority()) && id.startsWith("raw:")) {
                    File candidate = new File(id.substring(4)).getCanonicalFile();
                    if (candidate.isFile()) return candidate;
                }
            }
            try (Cursor c = context.getContentResolver().query(uri, new String[]{"_data"}, null, null, null)) {
                if (c != null && c.moveToFirst()) {
                    String path = c.getString(0);
                    if (path != null) {
                        File file = new File(path).getCanonicalFile();
                        if (file.isFile()) return file;
                    }
                }
            }
        } catch (Exception ignored) { }
        return null;
    }

    static Saved publish(Context context, Input input, File signed, int mode) throws IOException {
        String base = input.name.replaceFirst("(?i)\\.apk$", "").replaceAll("[^\\p{L}\\p{N}._ -]", "_");
        if (base.isEmpty()) base = input.metadata[0];
        while (base.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 160) {
            base = base.substring(0, base.offsetByCodePoints(base.length(), -1));
        }
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(new Date());
        String suffix = mode == 0 ? "-shield-" : mode == 3 ? "-signature-killer-" : mode == 4 ? "-signature-killer-v2-" : mode == 5 ? "-signature-killer-v3-" : mode == 6 ? "-fancy-bypass-" : "-strings-v" + mode + "-";
        String name = base + suffix + stamp + "-" + UUID.randomUUID().toString().substring(0, 6) + ".apk";
        File parent = input.original == null ? null : input.original.getParentFile();
        if (parent != null && parent.isDirectory() && parent.canWrite()) {
            try { return localSave(signed, parent, name, true); }
            catch (IOException ignored) { }
        }
        if (Build.VERSION.SDK_INT < 29) {
            File downloads = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "DEX Protection");
            if (!downloads.isDirectory() && !downloads.mkdirs()) throw new IOException("Cannot create Downloads/DEX Protection. Allow storage access.");
            return localSave(signed, downloads, name, false);
        }
        ContentResolver resolver = context.getContentResolver();
        ContentValues values = new ContentValues();
        values.put(MediaStore.Downloads.DISPLAY_NAME, name);
        values.put(MediaStore.Downloads.MIME_TYPE, "application/vnd.android.package-archive");
        values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/DEX Protection");
        values.put(MediaStore.Downloads.IS_PENDING, 1);
        Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
        if (uri == null) throw new IOException("Cannot create output in Downloads.");
        try {
            try (InputStream in = new FileInputStream(signed); OutputStream out = resolver.openOutputStream(uri, "w")) {
                if (out == null) throw new IOException("Cannot write output.");
                copy(in, out);
            }
            ContentValues ready = new ContentValues();
            ready.put(MediaStore.Downloads.IS_PENDING, 0);
            if (resolver.update(uri, ready, null, null) != 1) throw new IOException("Cannot finalize saved APK.");
            return new Saved(uri, "Downloads/DEX Protection/" + name, false);
        } catch (IOException | RuntimeException error) {
            resolver.delete(uri, null, null);
            throw error;
        }
    }

    private static Saved localSave(File source, File folder, String name, boolean besideInput) throws IOException {
        File destination = new File(folder, name);
        if (destination.exists()) throw new IOException("Output filename already exists.");
        File partial = File.createTempFile(".dexpack-", ".part", folder);
        try {
            try (InputStream in = new FileInputStream(source); FileOutputStream out = new FileOutputStream(partial)) {
                copy(in, out); out.getFD().sync();
            }
            if (destination.exists()) throw new IOException("Output filename already exists.");
            try { Files.move(partial.toPath(), destination.toPath(), StandardCopyOption.ATOMIC_MOVE); }
            catch (java.nio.file.AtomicMoveNotSupportedException e) { Files.move(partial.toPath(), destination.toPath()); }
            return new Saved(Uri.fromFile(destination), destination.getAbsolutePath(), besideInput);
        } finally { if (partial.exists() && !partial.delete()) partial.deleteOnExit(); }
    }

    static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[1024 * 1024];
        for (;;) {
            if (Thread.currentThread().isInterrupted()) throw new IOException("Processing cancelled.");
            int length = in.read(buffer);
            if (length < 0) break;
            if (length != 0) out.write(buffer, 0, length);
        }
    }
}
