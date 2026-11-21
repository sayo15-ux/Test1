package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

final class SigningSettings extends Dialog {
    private final ProtectionApp app;
    private final Runnable pick;
    private final Consumer<Signing.Identity> accepted;
    private Uri uri;
    private EditText storePassword, keyPassword, alias;
    private TextView file, status, issue, load;
    SigningSettings(Context context, ProtectionApp app, Runnable pick, Consumer<Signing.Identity> accepted) {
        super(context, android.R.style.Theme_Material_Light_NoActionBar); Ui.registerDialog(context, this); this.app = app; this.pick = pick; this.accepted = accepted;
    }
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state); Context c = getContext(); LinearLayout page = Ui.column(c);
        LinearLayout bar = Ui.row(c); bar.setPadding(Ui.dp(c, 8), Ui.dp(c, 4), Ui.dp(c, 8), Ui.dp(c, 4));
        Ui.Icon back = Ui.iconButton(c, "back", Ui.INK, "Back"); bar.addView(back, Ui.lp(c, 40, 48)); back.setOnClickListener(v -> dismiss());
        TextView title = Ui.text(c, "Signing settings", 22, Ui.INK, false); LinearLayout.LayoutParams tp = Ui.lp(c, -2, -2); tp.leftMargin = Ui.dp(c, 8); bar.addView(title, tp); page.addView(bar, Ui.lp(c, -1, 64));
        ScrollView scroll = new ScrollView(c); LinearLayout content = Ui.column(c); content.setPadding(Ui.dp(c, 20), Ui.dp(c, 16), Ui.dp(c, 20), Ui.dp(c, 30)); scroll.addView(content); page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        status = Ui.text(c, "", 12, Ui.MUTED, false); Ui.line(status, 18); content.addView(status); updateStatus();
        TextView useDefault = Ui.button(c, "Use built-in key", true); addButton(content, useDefault);
        useDefault.setOnClickListener(v -> { if (!app.busy) { app.signer = null; app.notifyState(); updateStatus(); } });
        TextView choose = Ui.button(c, "Select keystore", false); Ui.outline(choose, Ui.LINE, 24); addButton(content, choose); choose.setOnClickListener(v -> { if (!app.busy) pick.run(); });
        file = Ui.text(c, "JKS / PKCS#12 / BKS", 12, Ui.MUTED, false); Ui.line(file, 18); content.addView(file);
        storePassword = field(content, "Keystore password", true); keyPassword = field(content, "Key password · blank = same", true); alias = field(content, "Alias · optional for one key", false);
        load = Ui.button(c, "Load key", true); load.setTag("loadKey"); addButton(content, load); load.setEnabled(false); Ui.ripple(load, 0xffe7e0e8, 24); load.setTextColor(0xffaaa3ad); load.setOnClickListener(v -> load());
        issue = Ui.text(c, "", 12, Ui.ERROR, false); Ui.line(issue, 17); content.addView(issue);
        FrameLayout screen = Ui.centered(c, page); setContentView(screen); Ui.systemBars(getWindow(), screen); Ui.appear(page);
    }
    private void addButton(LinearLayout content, TextView button) { LinearLayout.LayoutParams p = Ui.lp(getContext(), -1, 42); p.topMargin = Ui.dp(getContext(), 12); p.bottomMargin = Ui.dp(getContext(), 12); content.addView(button, p); }
    private EditText field(LinearLayout content, String name, boolean password) {
        Context c = getContext(); TextView label = Ui.text(c, name, 12, Ui.MUTED, false); content.addView(label); Ui.marginTop(label, 18);
        EditText edit = new EditText(c); edit.setSingleLine(); edit.setTextSize(14); edit.setTextColor(Ui.INK); edit.setPadding(Ui.dp(c, 12), 0, Ui.dp(c, 12), 0); Ui.outline(edit, Ui.LINE, 8);
        edit.setInputType(InputType.TYPE_CLASS_TEXT | (password ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS)); edit.setContentDescription(name);
        content.addView(edit, Ui.lp(c, -1, 48)); Ui.marginTop(edit, 6); return edit;
    }
    void setKeystore(Uri value) { uri = value; if (file == null) return; file.setText(value.getLastPathSegment()); load.setEnabled(true); load.setTextColor(Color.WHITE); Ui.ripple(load, Ui.PURPLE, 24); issue.setText(""); }
    private void updateStatus() { status.setText(app.signer == null ? "Built-in key · new installs" : app.signer.name + " · " + app.signer.algorithm()); }
    private void load() {
        if (uri == null || app.busy) return;
        final Uri source = uri; final String name = alias.getText().toString().trim();
        final char[] store = storePassword.getText().toString().toCharArray(), key = keyPassword.getText().toString().toCharArray(); storePassword.setText(""); keyPassword.setText("");
        app.busy = true; app.notifyState(); load.setEnabled(false); issue.setTextColor(Ui.MUTED); issue.setText("Loading key…");
        app.worker.execute(() -> {
            try {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                try (InputStream input = getContext().getContentResolver().openInputStream(source)) { if (input == null) throw new java.io.IOException("Cannot read keystore."); Storage.copy(input, bytes); }
                byte[] encoded = bytes.toByteArray(); List<Signing.Identity> keys;
                try { keys = Signing.importStore(encoded, store, key); } finally { Arrays.fill(encoded, (byte) 0); }
                Signing.Identity chosen = null;
                for (Signing.Identity candidate : keys) if (candidate.name.equals(name) || name.isEmpty() && keys.size() == 1) { chosen = candidate; break; }
                if (chosen == null) throw new java.io.IOException(name.isEmpty() ? "Enter an alias; this keystore contains multiple keys." : "This alias was not found in the keystore.");
                final Signing.Identity identity = chosen;
                app.main.post(() -> { app.busy = false; app.signer = identity; app.notifyState(); if (isShowing()) { updateStatus(); issue.setText("Key loaded"); issue.setTextColor(Ui.PURPLE); load.setEnabled(true); accepted.accept(identity); } });
            } catch (Exception error) {
                String message = error.getMessage() == null ? "Cannot import signing key." : error.getMessage();
                app.main.post(() -> { app.busy = false; app.notifyState(); if (isShowing()) { issue.setText(message); issue.setTextColor(Ui.ERROR); load.setEnabled(true); } });
            } finally { Arrays.fill(store, '\0'); Arrays.fill(key, '\0'); }
        });
    }
}
