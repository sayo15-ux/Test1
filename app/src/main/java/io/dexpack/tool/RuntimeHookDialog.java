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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Locale;
import java.util.Properties;
import java.util.regex.Pattern;

/** Configuration screen for the SigFall-style runtime signature interceptor. */
final class RuntimeHookDialog extends Dialog {
    private static final Pattern PACKAGE_NAME =
            Pattern.compile("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*$");

    private final ProtectionApp app;
    private final Runnable pick;
    private final ArrayList<String> targets = new ArrayList<>();
    private EditText targetField;
    private LinearLayout targetList;
    private TextView framework, status, certificate, add, choose, clear, save;
    private String certificateBase64 = "";
    private String certificateSha256 = "";

    RuntimeHookDialog(Context context, ProtectionApp app, Runnable pick) {
        super(context, android.R.style.Theme_Material_Light_NoActionBar);
        Ui.registerDialog(context, this);
        this.app = app;
        this.pick = pick;
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        load();
        Context c = getContext();
        LinearLayout page = Ui.column(c);
        LinearLayout bar = Ui.row(c);
        bar.setPadding(Ui.dp(c, 8), Ui.dp(c, 4), Ui.dp(c, 8), Ui.dp(c, 4));
        Ui.Icon back = Ui.iconButton(c, "back", Ui.INK, "Back");
        back.setOnClickListener(v -> dismiss());
        bar.addView(back, Ui.lp(c, 40, 48));
        TextView title = Ui.text(c, "Runtime Hook", 22, Ui.INK, false);
        LinearLayout.LayoutParams titleParams = Ui.lp(c, -2, -2);
        titleParams.leftMargin = Ui.dp(c, 8);
        bar.addView(title, titleParams);
        page.addView(bar, Ui.lp(c, -1, 64));

        ScrollView scroll = new ScrollView(c);
        LinearLayout content = Ui.column(c);
        content.setPadding(Ui.dp(c, 20), Ui.dp(c, 16), Ui.dp(c, 20), Ui.dp(c, 30));
        scroll.addView(content);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        framework = Ui.text(c, "", 12, Ui.MUTED, false);
        Ui.line(framework, 17);
        content.addView(framework);
        TextView explain = Ui.text(c,
                "Intercepts Java-layer PackageManager signature responses for the target packages. "
                        + "It does not modify APK files and does not bypass native, file-read or "
                        + "self-integrity checks.", 12, Ui.MUTED, false);
        Ui.line(explain, 17);
        content.addView(explain);
        Ui.marginTop(explain, 8);

        TextView targetLabel = Ui.text(c, "Target package", 12, Ui.MUTED, false);
        content.addView(targetLabel);
        Ui.marginTop(targetLabel, 18);
        targetField = new EditText(c);
        targetField.setSingleLine();
        targetField.setHint("com.example.app");
        targetField.setTextSize(14);
        targetField.setTextColor(Ui.INK);
        targetField.setPadding(Ui.dp(c, 12), 0, Ui.dp(c, 12), 0);
        Ui.outline(targetField, Ui.LINE, 8);
        targetField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        targetField.setContentDescription("Target package name");
        targetField.setTag("runtimeHookTargetField");
        content.addView(targetField, Ui.lp(c, -1, 48));

        add = Ui.button(c, "Add target", false);
        Ui.outline(add, Ui.LINE, 24);
        add.setTag("runtimeHookAddTarget");
        addButton(content, add);
        add.setOnClickListener(v -> addTarget());

        TextView listLabel = Ui.text(c, "Targets", 12, Ui.MUTED, false);
        content.addView(listLabel);
        Ui.marginTop(listLabel, 10);
        targetList = Ui.column(c);
        targetList.setTag("runtimeHookTargetList");
        content.addView(targetList, Ui.lp(c, -1, -2));

        choose = Ui.button(c, "Choose signature-source APK", false);
        Ui.outline(choose, Ui.LINE, 24);
        choose.setTag("runtimeHookChooseCert");
        addButton(content, choose);
        choose.setOnClickListener(v -> {
            if (!app.busy) pick.run();
        });

        certificate = Ui.text(c, "", 11, Ui.INK, false);
        Ui.line(certificate, 16);
        certificate.setTag("runtimeHookCertificate");
        content.addView(certificate);
        Ui.marginTop(certificate, 8);

        clear = Ui.button(c, "Clear certificate", false);
        Ui.outline(clear, Ui.LINE, 24);
        addButton(content, clear);
        clear.setOnClickListener(v -> {
            certificateBase64 = "";
            certificateSha256 = "";
            refreshCertificate();
            status.setText("Certificate cleared. Tap Save configuration to persist.");
            status.setTextColor(Ui.MUTED);
        });

        save = Ui.button(c, "Save configuration", true);
        save.setTag("runtimeHookSave");
        addButton(content, save);
        save.setOnClickListener(v -> save());

        status = Ui.text(c, "", 12, Ui.MUTED, false);
        Ui.line(status, 17);
        status.setTag("runtimeHookStatus");
        content.addView(status);
        Ui.marginTop(status, 8);

        FrameLayout screen = Ui.centered(c, page);
        setContentView(screen);
        Ui.systemBars(getWindow(), screen);
        Ui.appear(page);
        refreshTargets();
        refreshCertificate();
        framework.setText(frameworkStatus());
    }

    private void addButton(LinearLayout content, TextView button) {
        LinearLayout.LayoutParams params = Ui.lp(getContext(), -1, 42);
        params.topMargin = Ui.dp(getContext(), 10);
        params.bottomMargin = Ui.dp(getContext(), 10);
        content.addView(button, params);
    }

    private void load() {
        Properties stored = HookConfig.read(getContext());
        targets.clear();
        targets.addAll(HookConfig.split(stored.getProperty(HookConfig.KEY_TARGETS, "")));
        certificateBase64 = stored.getProperty(HookConfig.KEY_CERTIFICATE, "").trim();
        certificateSha256 = fingerprint(certificateBase64);
    }

    private void addTarget() {
        String value = targetField.getText().toString().trim();
        if (value.isEmpty() || !PACKAGE_NAME.matcher(value).matches()) {
            status.setText("Enter a valid package name, for example com.example.app.");
            status.setTextColor(Ui.ERROR);
            return;
        }
        if (!targets.contains(value)) targets.add(value);
        targetField.setText("");
        refreshTargets();
        status.setText("Target added. Tap Save configuration to persist.");
        status.setTextColor(Ui.MUTED);
    }

    private void refreshTargets() {
        if (targetList == null) return;
        Context c = getContext();
        targetList.removeAllViews();
        if (targets.isEmpty()) {
            targetList.addView(Ui.text(c, "No targets configured.", 12, Ui.MUTED, false));
            return;
        }
        for (int i = 0; i < targets.size(); i++) {
            final int index = i;
            LinearLayout row = Ui.row(c);
            TextView label = Ui.text(c, targets.get(i), 12, Ui.INK, false);
            row.addView(label, new LinearLayout.LayoutParams(0, Ui.dp(c, 28), 1));
            TextView remove = Ui.text(c, "Remove", 12, Ui.ERROR, false);
            remove.setTag("runtimeHookRemoveTarget");
            Ui.ripple(remove, Color.TRANSPARENT, 8);
            remove.setOnClickListener(v -> {
                targets.remove(index);
                refreshTargets();
            });
            row.addView(remove, Ui.lp(c, -2, 32));
            targetList.addView(row, Ui.lp(c, -1, 32));
        }
    }

    private void refreshCertificate() {
        if (certificate == null) return;
        if (certificateBase64.isEmpty()) {
            certificate.setText("No replacement certificate selected. The hook will stay inactive.");
            return;
        }
        if (certificateSha256.isEmpty()) {
            certificate.setText("The stored certificate could not be decoded. Choose another APK.");
            return;
        }
        certificate.setText("Certificate loaded\nSHA-256: " + certificateSha256
                + "\nBase64 length: " + certificateBase64.length());
    }

    private void save() {
        try {
            HookConfig.write(getContext(), targets, certificateBase64);
            status.setText("Saved. Enable the module in Xposed/LSPosed and restart target apps.");
            status.setTextColor(Ui.PURPLE);
        } catch (Throwable error) {
            status.setText("Cannot save configuration: " + message(error));
            status.setTextColor(Ui.ERROR);
        }
    }

    void setCertificateUri(Uri uri) {
        if (uri == null || app.busy) return;
        app.busy = true;
        app.notifyState();
        choose.setEnabled(false);
        status.setText("Reading certificate from " + uri.getLastPathSegment() + "...");
        status.setTextColor(Ui.MUTED);
        app.worker.execute(() -> {
            File temporary = null;
            try {
                File direct = Storage.resolveFile(getContext(), uri);
                File apk = direct;
                if (apk == null || !apk.isFile()) {
                    temporary = File.createTempFile("hook-cert-", ".apk", getContext().getCacheDir());
                    try (InputStream input = getContext().getContentResolver().openInputStream(uri);
                         FileOutputStream output = new FileOutputStream(temporary)) {
                        if (input == null) throw new IOException("Cannot open this APK.");
                        Storage.copy(input, output);
                        output.getFD().sync();
                    }
                    apk = temporary;
                }
                SignatureInspector.CertificateSource source = SignatureInspector.primaryCertificate(apk);
                String base64 = source.base64, sha256 = source.sha256, subject = source.subject;
                app.main.post(() -> {
                    app.busy = false;
                    app.notifyState();
                    if (isShowing()) {
                        certificateBase64 = base64;
                        certificateSha256 = sha256;
                        refreshCertificate();
                        choose.setEnabled(true);
                        status.setText("Using certificate: " + subject);
                        status.setTextColor(Ui.PURPLE);
                    }
                });
            } catch (Exception error) {
                String text = message(error);
                app.main.post(() -> {
                    app.busy = false;
                    app.notifyState();
                    if (isShowing()) {
                        choose.setEnabled(true);
                        status.setText("Cannot read certificate: " + text);
                        status.setTextColor(Ui.ERROR);
                    }
                });
            } finally {
                if (temporary != null && !temporary.delete()) temporary.deleteOnExit();
            }
        });
    }

    private static String frameworkStatus() {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return "Xposed framework detected. Keep this module enabled, add targets to its scope, and restart target apps.";
        } catch (Throwable ignored) {
            return "Xposed framework not detected in this process. Install/enable LSPosed or Xposed, enable this module and add target apps to its scope.";
        }
    }

    private static String fingerprint(String base64) {
        try {
            byte[] encoded = Base64.getDecoder().decode(base64);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(encoded);
            StringBuilder text = new StringBuilder();
            for (byte value : digest) text.append(String.format(Locale.ROOT, "%02X", value & 255));
            return text.toString();
        } catch (Exception error) {
            return "";
        }
    }

    private static String message(Throwable error) {
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }
}
