package io.dexpack.tool;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;

final class SigningDialog {
    private final Ui.Sheet dialog;
    private final Ui.Choice[] checks = new Ui.Choice[3];
    private final LinearLayout keyName;
    private final TextView alias;
    private final ProtectionApp app;
    private final Context context;

    SigningDialog(Context c, ProtectionApp app, boolean processing, Runnable importKey, Runnable confirmAction) {
        this.context = c; this.app = app;
        LinearLayout content = Ui.column(c); content.setPadding(Ui.dp(c, 18), Ui.dp(c, 20), Ui.dp(c, 18), Ui.dp(c, 14));
        TextView title = Ui.text(c, "Select signing key", 16, Ui.INK, true); title.setLetterSpacing(.15f / 16); content.addView(title);
        TextView label = Ui.text(c, "Signing key", 14, 0xff49454f, false); content.addView(label); Ui.marginTop(label, 22);
        LinearLayout key = Ui.row(c); key.setTag("signingKey"); key.setPadding(Ui.dp(c, 18), Ui.dp(c, 10), Ui.dp(c, 18), Ui.dp(c, 10)); key.setMinimumHeight(Ui.dp(c, 56)); Ui.outline(key, Ui.LINE, 30); key.setFocusable(true);
        key.addView(new Ui.Icon(c, "key", Ui.PURPLE), Ui.lp(c, 24, 24));
        LinearLayout copy = Ui.column(c); keyName = Ui.flow(c); copy.addView(keyName);
        alias = Ui.text(c, "", 12, 0xff49454f, false); copy.addView(alias); Ui.marginTop(alias, 5);
        LinearLayout.LayoutParams kp = new LinearLayout.LayoutParams(0, -2, 1); kp.leftMargin = Ui.dp(c, 12); kp.rightMargin = Ui.dp(c, 12); key.addView(copy, kp); key.addView(new Ui.Icon(c, "down", 0xff49454f).size(20), Ui.lp(c, 20, 20));
        content.addView(key, Ui.lp(c, -1, -2)); Ui.marginTop(key, 12); updateKey();
        TextView mode = Ui.text(c, "Signing mode", 14, 0xff49454f, false); content.addView(mode); Ui.marginTop(mode, 18);
        LinearLayout modes = Ui.row(c);
        for (int i = 0; i < 3; i++) {
            final int index = i; LinearLayout option = Ui.row(c); option.setTag("scheme" + (i + 1)); option.setFocusable(true); Ui.ripple(option, Color.TRANSPARENT, 4);
            Ui.Choice check = new Ui.Choice(c, true); checks[i] = check; check.checked(app.schemes[i], false); option.addView(check, Ui.lp(c, 20, 20));
            TextView name = Ui.text(c, "v" + (i + 1), 14, Ui.INK, false); Ui.line(name, 24); LinearLayout.LayoutParams np = Ui.lp(c, -2, -2); np.leftMargin = Ui.dp(c, 7); option.addView(name, np);
            LinearLayout.LayoutParams op = Ui.lp(c, -2, 40); if (i > 0) op.leftMargin = Ui.dp(c, 10); modes.addView(option, op);
            option.setContentDescription("APK signature v" + (i + 1)); option.setOnClickListener(v -> { checks[index].checked(!checks[index].selected, true); option.setSelected(checks[index].selected); });
        }
        content.addView(modes, Ui.lp(c, -1, 40)); Ui.marginTop(modes, 4);
        TextView issue = Ui.text(c, "", 12, Ui.ERROR, false); Ui.line(issue, 17); issue.setVisibility(View.GONE); content.addView(issue); Ui.marginTop(issue, 10);
        LinearLayout actions = Ui.row(c); actions.setGravity(Gravity.END); TextView cancel = Ui.button(c, "Cancel", false), confirm = Ui.button(c, "Confirm", true); confirm.setTag("confirmSigning");
        actions.addView(cancel, Ui.lp(c, -2, 40)); LinearLayout.LayoutParams cp = Ui.lp(c, -2, 40); cp.leftMargin = Ui.dp(c, 8); actions.addView(confirm, cp); content.addView(actions, Ui.lp(c, -1, -2)); Ui.marginTop(actions, 16);
        dialog = new Ui.Sheet(c, content, false); cancel.setOnClickListener(v -> dialog.dismiss());
        key.setOnClickListener(v -> {
            LinearLayout menu = Ui.column(c); menu.setBackground(Ui.shape(c, 0xfff4ebfa, 4));
            PopupWindow popup = new PopupWindow(menu, key.getWidth(), -2, true); popup.setBackgroundDrawable(new ColorDrawable(Color.TRANSPARENT)); popup.setElevation(Ui.dp(c, 6)); popup.setOutsideTouchable(true);
            String[] names = app.signer == null ? new String[]{"Default", "Import keystore"} : new String[]{"Default", app.signer.name, "Import keystore"};
            for (int i = 0; i < names.length; i++) {
                final int index = i; LinearLayout row = Ui.row(c); row.setMinimumHeight(Ui.dp(c, 48)); row.setPadding(Ui.dp(c, 16), Ui.dp(c, 12), Ui.dp(c, 16), Ui.dp(c, 12)); Ui.ripple(row, Color.TRANSPARENT, 4);
                row.addView(new Ui.Icon(c, "key", Ui.PURPLE), Ui.lp(c, 24, 24)); LinearLayout text = Ui.column(c); text.addView(Ui.text(c, names[i], 13, Ui.INK, false));
                if (i == 0) { TextView hint = Ui.text(c, "Built-in key", 11, Ui.MUTED, false); text.addView(hint); Ui.marginTop(hint, 4); }
                LinearLayout.LayoutParams tp = Ui.lp(c, -1, -2); tp.leftMargin = Ui.dp(c, 12); row.addView(text, tp); menu.addView(row, Ui.lp(c, -1, -2));
                row.setOnClickListener(item -> { popup.dismiss(); if (index == names.length - 1) { dialog.dismiss(); importKey.run(); } else if (index == 0) { app.signer = null; app.notifyState(); updateKey(); } });
            }
            popup.showAsDropDown(key); menu.setPivotY(0); if (android.animation.ValueAnimator.areAnimatorsEnabled()) { menu.setAlpha(0); menu.setScaleY(.94f); menu.animate().alpha(1).scaleY(1).setDuration(160).setInterpolator(Ui.MOTION).start(); }
        });
        confirm.setOnClickListener(v -> {
            boolean any = false; for (Ui.Choice check : checks) any |= check.selected;
            String message = any ? "" : "Select at least one signing mode.";
            if (any && processing && app.input != null) {
                if (app.input.minSdk() < 24 && !checks[0].selected) message = "Enable v1 for this APK’s older Android versions.";
                if (Integer.parseInt(app.input.metadata[3]) >= 30 && !checks[1].selected && !checks[2].selected) message = "Enable v2 or v3 for this APK.";
            }
            if (!message.isEmpty()) { issue.setText(message); issue.setVisibility(View.VISIBLE); return; }
            for (int i = 0; i < 3; i++) app.schemes[i] = checks[i].selected;
            dialog.dismiss(); confirmAction.run();
        });
    }
    private void updateKey() {
        keyName.removeAllViews(); keyName.addView(Ui.text(context, app.signer == null ? "Default" : app.signer.name, 14, Ui.INK, true));
        if (app.signer == null) addBadge("Default", false);
        addBadge(app.signer == null ? "RSA" : app.signer.algorithm(), true);
        alias.setText(app.signer == null ? "Built-in key" : "Alias: " + app.signer.name);
    }
    private void addBadge(String text, boolean outline) { LinearLayout.LayoutParams p = Ui.lp(context, -2, -2); p.leftMargin = Ui.dp(context, 8); keyName.addView(Ui.badge(context, text, outline), p); }
    void show() { dialog.show(); }
}
