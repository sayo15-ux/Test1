package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/** Full-screen result view for {@link SignatureInspector}. */
final class SignatureTestDialog extends Dialog {
    private final ProtectionApp app;
    private final Runnable pick;
    private TextView status, report, inspectSelected, inspectOther;
    private SignatureInspector.Report result;

    SignatureTestDialog(Context context, ProtectionApp app, Runnable pick) {
        super(context, android.R.style.Theme_Material_Light_NoActionBar);
        Ui.registerDialog(context, this);
        this.app = app;
        this.pick = pick;
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Context c = getContext();
        LinearLayout page = Ui.column(c);
        LinearLayout bar = Ui.row(c);
        bar.setPadding(Ui.dp(c, 8), Ui.dp(c, 4), Ui.dp(c, 8), Ui.dp(c, 4));
        Ui.Icon back = Ui.iconButton(c, "back", Ui.INK, "Back");
        back.setOnClickListener(v -> dismiss());
        bar.addView(back, Ui.lp(c, 40, 48));
        TextView title = Ui.text(c, "Test Signature", 22, Ui.INK, false);
        LinearLayout.LayoutParams titleParams = Ui.lp(c, -2, -2);
        titleParams.leftMargin = Ui.dp(c, 8);
        bar.addView(title, titleParams);
        page.addView(bar, Ui.lp(c, -1, 64));

        ScrollView scroll = new ScrollView(c);
        LinearLayout content = Ui.column(c);
        content.setPadding(Ui.dp(c, 20), Ui.dp(c, 16), Ui.dp(c, 20), Ui.dp(c, 30));
        scroll.addView(content);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));

        inspectSelected = Ui.button(c, "Inspect selected APK", true);
        inspectSelected.setTag("inspectSelected");
        addButton(content, inspectSelected);
        inspectSelected.setOnClickListener(v -> inspectSelected());

        inspectOther = Ui.button(c, "Choose another APK", false);
        Ui.outline(inspectOther, Ui.LINE, 24);
        inspectOther.setTag("inspectOtherApk");
        addButton(content, inspectOther);
        inspectOther.setOnClickListener(v -> {
            if (!app.busy) pick.run();
        });

        status = Ui.text(c, "", 12, Ui.MUTED, false);
        Ui.line(status, 18);
        content.addView(status);
        Ui.marginTop(status, 16);
        report = Ui.text(c, "", 11, Ui.INK, false);
        Ui.line(report, 17);
        report.setTypeface(Typeface.MONOSPACE);
        report.setTag("signatureReport");
        content.addView(report);
        Ui.marginTop(report, 8);

        FrameLayout screen = Ui.centered(c, page);
        setContentView(screen);
        Ui.systemBars(getWindow(), screen);
        Ui.appear(page);
        update();
    }

    private void addButton(LinearLayout content, TextView button) {
        LinearLayout.LayoutParams params = Ui.lp(getContext(), -1, 42);
        params.topMargin = Ui.dp(getContext(), 12);
        params.bottomMargin = Ui.dp(getContext(), 12);
        content.addView(button, params);
    }

    void inspectSelected() {
        if (app.input != null) inspect(app.input.cached);
    }

    void inspectUri(Uri uri) {
        if (uri == null) return;
        try {
            File direct = Storage.resolveFile(getContext(), uri);
            if (direct != null && direct.isFile()) {
                inspect(direct);
                return;
            }
            File cached = File.createTempFile("signature-test-", ".apk", getContext().getCacheDir());
            try (InputStream input = getContext().getContentResolver().openInputStream(uri);
                 FileOutputStream output = new FileOutputStream(cached)) {
                if (input == null) throw new java.io.IOException("Cannot open this APK.");
                Storage.copy(input, output);
                output.getFD().sync();
            } catch (Exception error) {
                if (!cached.delete()) cached.deleteOnExit();
                throw error;
            }
            inspect(cached);
        } catch (Exception error) {
            status.setText("Cannot open APK: " + message(error));
            status.setTextColor(Ui.ERROR);
        }
    }

    void inspect(File apk) {
        if (apk == null) {
            status.setText("No APK was selected.");
            status.setTextColor(Ui.ERROR);
            return;
        }
        if (app.busy) {
            status.setText("Wait for the current operation to finish.");
            status.setTextColor(Ui.MUTED);
            return;
        }
        app.busy = true;
        app.notifyState();
        status.setTextColor(Ui.MUTED);
        status.setText("Inspecting " + apk.getName() + "...");
        report.setText("");
        app.worker.execute(() -> {
            SignatureInspector.Report value = SignatureInspector.inspect(apk);
            app.main.post(() -> {
                app.busy = false;
                app.notifyState();
                result = value;
                update();
            });
        });
    }

    private void update() {
        if (inspectSelected != null) inspectSelected.setEnabled(!app.busy && app.input != null);
        if (inspectOther != null) inspectOther.setEnabled(!app.busy);
        if (status == null || report == null || app.busy) return;
        if (result == null) {
            status.setText(app.input == null
                    ? "Select an APK on the main screen, or choose one here."
                    : "Ready to inspect the selected APK.");
            status.setTextColor(Ui.MUTED);
            report.setText("");
            return;
        }
        status.setText(result.status());
        status.setTextColor(result.inspected() && result.valid ? Ui.PURPLE : Ui.ERROR);
        report.setText(result.text());
    }

    private static String message(Exception error) {
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }
}
