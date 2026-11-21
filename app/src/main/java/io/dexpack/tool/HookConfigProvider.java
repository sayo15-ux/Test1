package io.dexpack.tool;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;

import java.util.Properties;

/**
 * Exposes the hook configuration to hooked apps when XSharedPreferences is not
 * readable. The provider is read-only; the certificate is public key material.
 */
public final class HookConfigProvider extends ContentProvider {
    private static final UriMatcher MATCHER = new UriMatcher(UriMatcher.NO_MATCH);
    private static final int CONFIG = 1;

    static {
        MATCHER.addURI(HookConfig.AUTHORITY, "config", CONFIG);
    }

    @Override public boolean onCreate() { return true; }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) {
        if (MATCHER.match(uri) != CONFIG || getContext() == null) return null;
        Properties stored = HookConfig.read(getContext());
        String serialized = HookConfig.format(
                HookConfig.split(stored.getProperty(HookConfig.KEY_TARGETS, "")),
                stored.getProperty(HookConfig.KEY_CERTIFICATE, ""));
        MatrixCursor cursor = new MatrixCursor(new String[]{"config"});
        cursor.addRow(new Object[]{serialized});
        return cursor;
    }

    @Override public String getType(Uri uri) {
        return MATCHER.match(uri) == CONFIG ? "text/plain" : null;
    }

    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("Hook configuration is read-only.");
    }

    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("Hook configuration is read-only.");
    }

    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("Hook configuration is read-only.");
    }
}
