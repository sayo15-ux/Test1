package io.dexpack.tool;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.util.ArrayList;

public final class MainActivity extends Activity implements ProtectionApp.Observer {
    private static final int PICK_APK = 100, PICK_KEY = 101, STORAGE_ACCESS = 102, LEGACY_ACCESS = 103, PICK_TEST_APK = 104, PICK_CERT_APK = 105;
    private ProtectionApp app;
    private LinearLayout selectionCard, classArea, start;
    private TextView title, subtitle, path, count, startLabel, status, output;
    private Ui.Icon clear, next, clearClasses, startIcon;
    private FrameLayout iconBox;
    private final LinearLayout[] cards = new LinearLayout[4];
    private final LinearLayout[] copies = new LinearLayout[4];
    private final Ui.Choice[] choices = new Ui.Choice[4];
    private boolean pendingClasses, pendingBrowse, pendingProcess;
    private int previousMode = -2;
    private ExecutorDialog executor;
    private SigningSettings settings;
    private SignatureTestDialog signatureTest;
    private RuntimeHookDialog runtimeHook;
    private final ArrayList<Dialog> dialogs = new ArrayList<>();

    void trackDialog(Dialog dialog) { dialogs.add(dialog); dialog.setOnDismissListener(d -> dialogs.remove(dialog)); }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        app = (ProtectionApp) getApplication();
        buildHome(); app.observe(this);
        if (app.processing) showExecutor();
    }
    @Override protected void onDestroy() {
        app.detach(this);
        for (Dialog dialog : new ArrayList<>(dialogs)) { if (dialog instanceof Ui.Sheet) ((Ui.Sheet) dialog).dismissImmediately(); else dialog.dismiss(); }
        dialogs.clear();
        super.onDestroy();
    }

    private void buildHome() {
        boolean compact = getResources().getConfiguration().screenWidthDp <= 340;
        LinearLayout root = Ui.column(this); root.setBackgroundColor(Ui.SURFACE);
        LinearLayout bar = Ui.row(this); bar.setPadding(Ui.dp(this, 8), Ui.dp(this, 4), Ui.dp(this, 8), Ui.dp(this, 4));
        Ui.Icon menu = Ui.iconButton(this, "menu", Ui.INK, "Open menu"); menu.setTag("menu"); bar.addView(menu, Ui.lp(this, 40, 48)); menu.setOnClickListener(v -> drawer());
        TextView heading = Ui.text(this, "DEX Protection", 22, Ui.INK, false); heading.setSingleLine(); heading.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(0, -2, 1); hp.leftMargin = Ui.dp(this, 8); bar.addView(heading, hp); root.addView(bar, Ui.lp(this, -1, 64));
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true); scroll.setVerticalScrollBarEnabled(false); scroll.setClipToPadding(false); root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        LinearLayout content = Ui.column(this); content.setPadding(Ui.dp(this, compact ? 12 : 16), Ui.dp(this, compact ? 16 : 18), Ui.dp(this, compact ? 12 : 16), Ui.dp(this, compact ? 24 : 28)); scroll.addView(content);

        FrameLayout selection = new FrameLayout(this); selection.setTag("selectionCard"); selection.setBackground(Ui.shape(this, Ui.CARD, 10)); selection.setElevation(Ui.dp(this, 1));
        selectionCard = Ui.row(this); selectionCard.setTag("selectApk"); selectionCard.setPadding(Ui.dp(this, 16), Ui.dp(this, 12), Ui.dp(this, 16), Ui.dp(this, 12)); selectionCard.setMinimumHeight(Ui.dp(this, 72)); Ui.ripple(selectionCard, Ui.CARD, 10);
        iconBox = new FrameLayout(this); iconBox.setBackground(Ui.shape(this, Color.WHITE, 8)); iconBox.setClipToOutline(true); selectionCard.addView(iconBox, Ui.lp(this, 44, 44));
        LinearLayout text = Ui.column(this); title = Ui.text(this, "Select APK", 16, Ui.PURPLE, true); title.setMaxLines(1); title.setEllipsize(TextUtils.TruncateAt.END); text.addView(title);
        subtitle = Ui.text(this, "Not selected", 14, Ui.MUTED, false); subtitle.setMaxLines(1); subtitle.setEllipsize(TextUtils.TruncateAt.END); text.addView(subtitle); Ui.marginTop(subtitle, 8);
        path = Ui.text(this, "", 10, Ui.MUTED, false); Ui.line(path, 13); text.addView(path);
        LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(0, -2, 1); tp.leftMargin = Ui.dp(this, 12); selectionCard.addView(text, tp);
        next = new Ui.Icon(this, "next", Ui.MUTED); LinearLayout.LayoutParams np = Ui.lp(this, 24, 24); np.leftMargin = Ui.dp(this, 4); selectionCard.addView(next, np);
        selection.addView(selectionCard, new FrameLayout.LayoutParams(-1, -2));
        FrameLayout closeBox = new FrameLayout(this); closeBox.setTag("clearApkBox");
        View circle = new View(this); circle.setBackground(Ui.shape(this, 0x0d1d1b20, 11)); closeBox.addView(circle, new FrameLayout.LayoutParams(Ui.dp(this, 22), Ui.dp(this, 22), Gravity.CENTER));
        clear = Ui.iconButton(this, "close", Ui.ERROR, "Clear selected APK").size(18); clear.setTag("clearApk"); closeBox.addView(clear, new FrameLayout.LayoutParams(-1, -1)); clear.setOnClickListener(v -> app.clear());
        FrameLayout.LayoutParams closeParams = new FrameLayout.LayoutParams(Ui.dp(this, 40), Ui.dp(this, 40), Gravity.END | Gravity.CENTER_VERTICAL); closeParams.rightMargin = Ui.dp(this, 9); selection.addView(closeBox, closeParams);
        selectionCard.setFocusable(true); selectionCard.setOnClickListener(v -> chooseApk()); content.addView(selection, Ui.lp(this, -1, -2));

        String[] labels = {"Apk Shield", "Dex String Encryption V1", "Dex String Encryption V2", "Signature Killer"};
        String[] descriptions = {"Provides a shell for the APK to protect against decompilation.", "Encrypts strings in DEX files (Version 1).", "Encrypts strings in DEX files (Version 2).", "Removes in-app signature verification checks."};
        for (int i = 0; i < 4; i++) {
            final int feature = i; LinearLayout card = Ui.row(this); cards[i] = card; card.setTag("feature" + i);
            card.setPadding(Ui.dp(this, compact ? 12 : 16), Ui.dp(this, 12), Ui.dp(this, compact ? 12 : 18), Ui.dp(this, 12)); card.setMinimumHeight(Ui.dp(this, 64)); Ui.ripple(card, Ui.CARD, 12); card.setFocusable(true);
            LinearLayout copy = Ui.column(this); copies[i] = copy;
            LinearLayout label = Ui.flow(this); TextView name = Ui.text(this, labels[i], compact ? 13 : 14, Ui.INK, true); name.setLetterSpacing(.45f / (compact ? 13 : 14)); Ui.line(name, 20); label.addView(name);
            if (i != 1) { TextView vip = Ui.badge(this, "VIP", false); vip.setTextSize(10); vip.setLetterSpacing(.01f); vip.setPadding(Ui.dp(this, 6), 0, Ui.dp(this, 6), 0); LinearLayout.LayoutParams vp = Ui.lp(this, -2, -2); vp.leftMargin = Ui.dp(this, 7); label.addView(vip, vp); }
            copy.addView(label); TextView description = Ui.text(this, descriptions[i], 12, 0xff49454f, false); copy.addView(description); Ui.marginTop(description, 4);
            card.addView(copy, new LinearLayout.LayoutParams(0, -2, 1)); choices[i] = new Ui.Choice(this);
            LinearLayout.LayoutParams cp = Ui.lp(this, 22, 22); cp.leftMargin = Ui.dp(this, compact ? 10 : 16); card.addView(choices[i], cp);
            card.setContentDescription(labels[i]); card.setOnClickListener(v -> {
                if (!app.busy) { app.mode = app.mode == feature ? -1 : feature; app.saved = null; app.hasExecution = false; app.status = ""; app.failed = false; app.notifyState(); }
            });
            content.addView(card, Ui.lp(this, -1, -2)); Ui.marginTop(card, i == 0 ? 20 : 10);
        }
        classArea = Ui.column(this); classArea.setTag("classArea"); TextView classLabel = Ui.text(this, "", 14, Ui.PURPLE, true); classLabel.setLetterSpacing(.3f / 14); classLabel.setTag("classHeading"); classArea.addView(classLabel);
        LinearLayout classRow = Ui.row(this); classRow.setBackground(Ui.shape(this, Ui.CARD, 10));
        LinearLayout classButton = Ui.row(this); classButton.setTag("selectClasses"); classButton.setPadding(Ui.dp(this, 16), Ui.dp(this, 12), Ui.dp(this, 16), Ui.dp(this, 12)); Ui.ripple(classButton, Ui.CARD, 10);
        TextView selectLabel = Ui.text(this, "Select classes", 14, Ui.INK, false); selectLabel.setLetterSpacing(.3f / 14); classButton.addView(selectLabel, new LinearLayout.LayoutParams(0, -2, 1));
        count = Ui.text(this, "0 selected", 11, Ui.MUTED, false); Ui.line(count, 16); classButton.addView(count); classButton.setFocusable(true); classButton.setOnClickListener(v -> openClasses()); classRow.addView(classButton, new LinearLayout.LayoutParams(0, -2, 1));
        clearClasses = Ui.iconButton(this, "close", Ui.ERROR, "Clear class selection").size(19); clearClasses.setTag("clearClasses"); classRow.addView(clearClasses, Ui.lp(this, 36, 40)); clearClasses.setOnClickListener(v -> { if (!app.busy) { app.selection().clear(); app.notifyState(); } });
        classArea.addView(classRow, Ui.lp(this, -1, -2)); Ui.marginTop(classRow, 10); content.addView(classArea, Ui.lp(this, -1, -2)); Ui.marginTop(classArea, 18);

        start = Ui.row(this); start.setGravity(Gravity.CENTER); start.setFocusable(true); start.setTag("startProcessing"); start.setContentDescription("Start Processing"); Ui.ripple(start, Ui.PURPLE, 28);
        startIcon = new Ui.Icon(this, "check", Color.WHITE); start.addView(startIcon, Ui.lp(this, 24, 24));
        startLabel = Ui.text(this, "Start Processing", 16, Color.WHITE, true); Ui.line(startLabel, 20); startLabel.setLetterSpacing(.5f / 16);
        LinearLayout.LayoutParams sl = Ui.lp(this, -2, -2); sl.leftMargin = Ui.dp(this, 12); start.addView(startLabel, sl);
        content.addView(start, Ui.lp(this, -1, 50)); Ui.marginTop(start, 30); start.setOnClickListener(v -> showSigning(true));
        status = Ui.text(this, "", 12, Ui.MUTED, false); Ui.line(status, 17); status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE); content.addView(status, Ui.lp(this, -1, -2)); Ui.marginTop(status, 16);
        output = Ui.button(this, "View output", false); output.setTag("viewOutput"); LinearLayout.LayoutParams op = Ui.lp(this, -2, -2); op.gravity = Gravity.CENTER_HORIZONTAL; op.topMargin = Ui.dp(this, 8); content.addView(output, op); output.setOnClickListener(v -> showExecutor());
        FrameLayout screen = Ui.centered(this, root); setContentView(screen); Ui.systemBars(getWindow(), screen);
    }

    @Override public void changed() {
        if (isFinishing() || isDestroyed()) return;
        Storage.Input input = app.input;
        selectionCard.setEnabled(!app.busy); clear.setEnabled(!app.busy);
        title.setTextSize(input == null ? 16 : 14); Ui.line(title, input == null ? 22 : 18); title.setLetterSpacing(input == null ? 0 : .2f / 14); title.setText(input == null ? "Select APK" : input.label);
        subtitle.setTextSize(input == null ? 14 : 12); Ui.line(subtitle, input == null ? 20 : 16); subtitle.setText(input == null ? "Not selected" : input.metadata[0]); Ui.marginTop(subtitle, input == null ? 8 : 2);
        path.setText(input == null ? "" : input.location); path.setVisibility(input == null ? View.GONE : View.VISIBLE);
        ((View) clear.getParent()).setVisibility(input == null ? View.GONE : View.VISIBLE); next.setVisibility(input == null ? View.VISIBLE : View.GONE);
        selectionCard.setPadding(Ui.dp(this, 16), Ui.dp(this, 12), Ui.dp(this, input == null ? 16 : 44), Ui.dp(this, 12));
        if (iconBox.getTag() != input || iconBox.getChildCount() == 0) {
            iconBox.removeAllViews(); iconBox.setTag(input);
            if (input != null && input.icon != null) { ImageView image = new ImageView(this); image.setImageDrawable(input.icon); image.setScaleType(ImageView.ScaleType.FIT_CENTER); iconBox.addView(image, new FrameLayout.LayoutParams(-1, -1)); }
            else iconBox.addView(new Ui.Icon(this, "android", Ui.MUTED).size(28), new FrameLayout.LayoutParams(-1, -1));
        }
        for (int i = 0; i < 4; i++) {
            cards[i].setEnabled(!app.busy); cards[i].setSelected(app.mode == i);
            if (previousMode != app.mode) {
                Ui.ripple(cards[i], app.mode == i ? Ui.SELECTED : Ui.CARD, 12); choices[i].checked(app.mode == i, previousMode != -2);
                float alpha = app.mode >= 0 && app.mode != i ? .42f : 1;
                if (previousMode == -2 || !android.animation.ValueAnimator.areAnimatorsEnabled()) { copies[i].setAlpha(alpha); choices[i].setAlpha(alpha); }
                else { copies[i].animate().alpha(alpha).setDuration(160).start(); choices[i].animate().alpha(alpha).setDuration(160).start(); }
            }
        }
        previousMode = app.mode;
        boolean needsClasses = app.mode == 1 || app.mode == 2;
        classArea.setVisibility(needsClasses ? View.VISIBLE : View.GONE);
        ((TextView) classArea.findViewWithTag("classHeading")).setText("Select classes for String Encryption V" + app.mode);
        count.setText(app.selection().size() + " selected"); clearClasses.setVisibility(app.selection().isEmpty() ? View.GONE : View.VISIBLE); clearClasses.setEnabled(!app.busy);
        boolean ready = app.ready(); start.setEnabled(ready); int foreground = ready ? Color.WHITE : 0xffaaa3ad;
        startIcon.color(foreground); startLabel.setTextColor(foreground); Ui.ripple(start, ready ? Ui.PURPLE : 0xffe7e0e8, 28); start.setElevation(Ui.dp(this, ready ? 6 : 0));
        String notice = input != null && !input.metadata[1].isEmpty() ? "Existing " + input.metadata[1] + " apps require the matching signing key." : "";
        String inline = app.hasExecution && !app.failed ? notice : app.status.isEmpty() ? notice : app.status;
        status.setText(inline); status.setTextColor(app.failed ? Ui.ERROR : inline.equals(notice) ? 0xff755714 : Ui.MUTED); status.setVisibility(inline.isEmpty() ? View.GONE : View.VISIBLE);
        output.setVisibility(app.hasExecution ? View.VISIBLE : View.GONE);
        if (executor != null && executor.isShowing()) executor.update();
        if (app.busy) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON); else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        if (pendingClasses && !app.busy) { pendingClasses = false; if (app.allClasses != null) openClasses(); }
    }

    private void chooseApk() {
        if (app.busy) return;
        LinearLayout content = dialogContent("Select APK", 22); content.setPadding(Ui.dp(this, 18), Ui.dp(this, 20), Ui.dp(this, 18), Ui.dp(this, 18));
        Ui.Sheet dialog = new Ui.Sheet(this, content, false);
        String[] labels = {"Choose from file picker", "Choose from installed apps"};
        for (int i = 0; i < labels.length; i++) {
            final int option = i; LinearLayout row = Ui.row(this); row.setPadding(Ui.dp(this, 8), Ui.dp(this, 8), Ui.dp(this, 8), Ui.dp(this, 8)); row.setMinimumHeight(Ui.dp(this, 44)); Ui.ripple(row, Color.TRANSPARENT, 4);
            View radio = new View(this); GradientDrawable border = Ui.shape(this, Color.TRANSPARENT, 11); border.setStroke(Ui.dp(this, 2), 0xff49454f); radio.setBackground(border); row.addView(radio, Ui.lp(this, 22, 22));
            TextView label = Ui.text(this, labels[i], 16, Ui.INK, false); label.setLetterSpacing(.4f / 16); LinearLayout.LayoutParams lp = Ui.lp(this, -2, -2); lp.leftMargin = Ui.dp(this, 14); row.addView(label, lp); content.addView(row, Ui.lp(this, -1, -2));
            row.setFocusable(true); row.setOnClickListener(v -> { dialog.dismiss(); if (option == 0) browse(); else installedApps(); });
        }
        dialog.show();
    }

    private LinearLayout dialogContent(String heading, int bottom) {
        LinearLayout content = Ui.column(this); content.setPadding(Ui.dp(this, 18), Ui.dp(this, 20), Ui.dp(this, 18), Ui.dp(this, 14));
        TextView title = Ui.text(this, heading, 16, Ui.INK, true); title.setLetterSpacing(.15f / 16); content.addView(title); LinearLayout.LayoutParams p = (LinearLayout.LayoutParams) title.getLayoutParams(); p.bottomMargin = Ui.dp(this, bottom); title.setLayoutParams(p); return content;
    }

    private void showExecutor() {
        if (!app.hasExecution) return;
        if (executor != null && executor.isShowing()) return;
        executor = new ExecutorDialog(this, app); executor.show(); executor.update();
    }

    private void document(int request) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try { startActivityForResult(intent, request); }
        catch (android.content.ActivityNotFoundException error) { Toast.makeText(this, "No file picker is installed.", Toast.LENGTH_LONG).show(); }
    }

    private void browse() {
        if (Build.VERSION.SDK_INT >= 30 && !StorageAccess.hasAllFiles()) {
            new AlertDialog.Builder(this).setTitle("File access")
                    .setMessage("Allow file access to browse APKs and save output beside the original file.")
                    .setPositiveButton("Allow access", (d, w) -> { pendingBrowse = true; storageSettings(); })
                    .setNegativeButton("System picker", (d, w) -> document(PICK_APK)).show(); return;
        }
        if (Build.VERSION.SDK_INT < 30 && checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            pendingBrowse = true; requestPermissions(new String[]{Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, LEGACY_ACCESS); return;
        }
        new FileBrowser(this, file -> app.select(null, file), () -> document(PICK_APK)).show();
    }

    private void storageSettings() {
        if (Build.VERSION.SDK_INT >= 30) {
            try { startActivityForResult(new Intent(StorageAccess.APP_ACCESS_ACTION, Uri.parse("package:" + getPackageName())), STORAGE_ACCESS); }
            catch (android.content.ActivityNotFoundException error) { startActivityForResult(new Intent(StorageAccess.ACCESS_ACTION), STORAGE_ACCESS); }
        }
    }

    private void installedApps() {
        new InstalledApps(this, app.worker, file -> app.select(null, file)).show();
    }

    private void openSignatureTest() {
        if (app.busy) {
            Toast.makeText(this, "Wait for the current operation to finish.", Toast.LENGTH_SHORT).show();
            return;
        }
        signatureTest = new SignatureTestDialog(this, app, () -> document(PICK_TEST_APK));
        signatureTest.show();
        signatureTest.inspectSelected();
    }

    private void openRuntimeHook() {
        if (app.busy) {
            Toast.makeText(this, "Wait for the current operation to finish.", Toast.LENGTH_SHORT).show();
            return;
        }
        runtimeHook = new RuntimeHookDialog(this, app, () -> document(PICK_CERT_APK));
        runtimeHook.show();
    }

    private void openClasses() {
        if (app.input == null) { chooseApk(); return; }
        if (app.busy) return;
        if (app.allClasses == null) { pendingClasses = true; app.loadClasses(); return; }
        new ClassPicker(this, app.allClasses, app.selection(), "Select classes for String Encryption V" + app.mode, app::notifyState).show();
    }

    private void drawer() {
        FrameLayout frame = new FrameLayout(this);
        LinearLayout content = Ui.column(this); content.setPadding(Ui.dp(this, 12), Ui.dp(this, 28), Ui.dp(this, 12), Ui.dp(this, 28)); frame.addView(content, new FrameLayout.LayoutParams(-1, -1));
        TextView heading = Ui.text(this, "DEX Protection", 22, Ui.INK, false); heading.setPadding(Ui.dp(this, 16), 0, Ui.dp(this, 16), 0); content.addView(heading); Ui.marginTop(heading, 4);
        Ui.Sheet dialog = new Ui.Sheet(this, frame, true);
        String[] labels = {"Test Signature", "Runtime Hook", "Signing settings"};
        String[] icons = {"check", "android", "key"};
        String[] tags = {"drawerSignatureTest", "drawerRuntimeHook", "drawerKeySettings"};
        for (int i = 0; i < labels.length; i++) {
            final int item = i; LinearLayout row = Ui.row(this); row.setTag(tags[i]); row.setPadding(Ui.dp(this, 16), Ui.dp(this, 12), Ui.dp(this, 16), Ui.dp(this, 12)); Ui.ripple(row, i == 2 ? Color.TRANSPARENT : 0xffeaddff, 28);
            int color = i == 2 ? Ui.MUTED : 0xff21005d; row.addView(new Ui.Icon(this, icons[i], color), Ui.lp(this, 24, 24));
            TextView label = Ui.text(this, labels[i], 14, color, false); Ui.medium(label); LinearLayout.LayoutParams lp = Ui.lp(this, -2, -2); lp.leftMargin = Ui.dp(this, 14); row.addView(label, lp);
            content.addView(row, Ui.lp(this, -1, 48)); Ui.marginTop(row, i == 0 ? 28 : 0); row.setFocusable(true); row.setOnClickListener(v -> { dialog.dismiss(); if (item == 0) openSignatureTest(); else if (item == 1) openRuntimeHook(); else openKeySettings(false); });
        }
        TextView version = Ui.text(this, "Version " + BuildConfig.VERSION_NAME, 12, Ui.MUTED, false); FrameLayout.LayoutParams vp = new FrameLayout.LayoutParams(-2, -2, Gravity.BOTTOM | Gravity.START); vp.leftMargin = Ui.dp(this, 28); vp.bottomMargin = Ui.dp(this, 24); frame.addView(version, vp); dialog.show();
    }

    private void showSigning(boolean processAfter) {
        if (app.busy || (processAfter && !app.ready())) return;
        new SigningDialog(this, app, processAfter, () -> {
            openKeySettings(processAfter);
        }, () -> {
            if (!processAfter) return;
            if (Build.VERSION.SDK_INT < 29 && checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) { pendingProcess = true; requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, LEGACY_ACCESS); }
            else { app.process(); showExecutor(); }
        }).show();
    }

    private void openKeySettings(boolean processAfter) {
        settings = new SigningSettings(this, app, () -> document(PICK_KEY), identity -> {
            if (processAfter) { settings.dismiss(); showSigning(true); }
        });
        settings.show();
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == STORAGE_ACCESS) { if (pendingBrowse) { pendingBrowse = false; if (Build.VERSION.SDK_INT >= 30 && StorageAccess.hasAllFiles()) browse(); else document(PICK_APK); } return; }
        if (result != RESULT_OK || data == null || data.getData() == null) return;
        if (request == PICK_APK) app.select(data.getData(), null);
        if (request == PICK_KEY && settings != null && settings.isShowing()) settings.setKeystore(data.getData());
        if (request == PICK_TEST_APK && signatureTest != null && signatureTest.isShowing()) signatureTest.inspectUri(data.getData());
        if (request == PICK_CERT_APK && runtimeHook != null && runtimeHook.isShowing()) runtimeHook.setCertificateUri(data.getData());
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request != LEGACY_ACCESS) return;
        if (pendingBrowse) { pendingBrowse = false; if (checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) browse(); else document(PICK_APK); }
        if (pendingProcess) { pendingProcess = false; if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) { app.process(); showExecutor(); } else { app.failed = true; app.status = "Storage access is needed to save output on this Android version."; app.notifyState(); } }
    }
}
