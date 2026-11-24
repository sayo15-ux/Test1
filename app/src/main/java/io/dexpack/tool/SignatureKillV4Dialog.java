package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import java.util.function.Consumer;

final class SignatureKillV4Dialog extends Dialog {
    private static final int BACKGROUND = 0xff111116;
    private static final int LINE = 0xff3f3f4b;
    private static final int ACCENT = 0xffbb86fc;
    private static final int INK = 0xfff5f5f7;
    private static final int MUTED = 0xffb5b5c2;

    private final ProtectionApp app;

    SignatureKillV4Dialog(Context context, ProtectionApp app) {
        super(context, android.R.style.Theme_Material_Dialog_NoActionBar);
        Ui.registerDialog(context, this);
        this.app = app;
        requestWindowFeature(Window.FEATURE_NO_TITLE);
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Context c = getContext();
        SignatureKillV4Config config = SignatureKillV4Config.load(c);
        LinearLayout content = Ui.column(c);
        content.setPadding(Ui.dp(c, 20), Ui.dp(c, 20), Ui.dp(c, 20), Ui.dp(c, 18));

        TextView title = Ui.text(c, "Signature Kill v4", 20, INK, true);
        title.setTag("sigKillV4Title");
        content.addView(title);
        TextView subtitle = Ui.text(c, "Fancy-style proxy application/factory bypass", 12, MUTED, false);
        Ui.line(subtitle, 17);
        content.addView(subtitle);
        Ui.marginTop(subtitle, 4);

        TextView modeLabel = section(content, "Options");
        Ui.marginTop(modeLabel, 18);
        addToggle(content, "PackageManager proxy", config.pmProxy, "sigKillV4PmProxy", v -> config.pmProxy = v);
        addToggle(content, "Patch SigningInfo reflection", config.patchSigningInfo, "sigKillV4SigningInfo", v -> config.patchSigningInfo = v);
        addToggle(content, "Delegate original Application", config.delegateOriginalApplication, "sigKillV4DelegateApp", v -> config.delegateOriginalApplication = v);
        addToggle(content, "Replace APK path", config.replaceApkPath, "sigKillV4ReplacePath", v -> config.replaceApkPath = v);
        addToggle(content, "Patch ApplicationInfo paths", config.patchApplicationInfo, "sigKillV4ApplicationInfo", v -> config.patchApplicationInfo = v);
        addToggle(content, "Embed original APK asset", config.embedOriginalApk, "sigKillV4EmbedApk", v -> config.embedOriginalApk = v);
        addToggle(content, "Debuggable manifest flag", config.debuggable, "sigKillV4Debuggable", v -> config.debuggable = v);

        LinearLayout actions = Ui.row(c);
        actions.setGravity(Gravity.END);
        TextView cancel = darkButton(c, "CANCEL", false);
        cancel.setTag("sigKillV4Cancel");
        TextView confirm = darkButton(c, "SAVE", true);
        confirm.setTag("sigKillV4Confirm");
        actions.addView(cancel, Ui.lp(c, -2, 40));
        LinearLayout.LayoutParams confirmParams = Ui.lp(c, -2, 40);
        confirmParams.leftMargin = Ui.dp(c, 10);
        actions.addView(confirm, confirmParams);
        content.addView(actions, Ui.lp(c, -1, -2));
        Ui.marginTop(actions, 16);

        cancel.setOnClickListener(v -> dismiss());
        confirm.setOnClickListener(v -> {
            try {
                config.save(c);
                app.notifyState();
                dismiss();
            } catch (Exception error) {
                android.widget.Toast.makeText(c, error.getMessage() == null ? "Cannot save." : error.getMessage(), android.widget.Toast.LENGTH_LONG).show();
            }
        });

        ScrollView scroll = new ScrollView(c) {
            @Override protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int maximum = getResources().getDisplayMetrics().heightPixels - Ui.dp(getContext(), 88);
                super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(maximum, View.MeasureSpec.AT_MOST));
            }
        };
        scroll.setVerticalScrollBarEnabled(false);
        scroll.addView(content);
        setContentView(scroll);
        setCanceledOnTouchOutside(true);

        Window window = getWindow();
        if (window != null) {
            window.setBackgroundDrawable(Ui.shape(c, BACKGROUND, 16));
            window.getDecorView().setSystemUiVisibility(0);
            window.setStatusBarColor(BACKGROUND);
            window.setNavigationBarColor(BACKGROUND);
            WindowManager.LayoutParams params = window.getAttributes();
            int screen = c.getResources().getDisplayMetrics().widthPixels;
            params.width = Math.min(Ui.dp(c, 420), screen - Ui.dp(c, 24));
            params.height = -2;
            params.gravity = Gravity.CENTER;
            params.dimAmount = .72f;
            window.setAttributes(params);
            window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
        }
        Ui.appear(content);
    }

    private TextView section(LinearLayout parent, String label) {
        TextView view = Ui.text(getContext(), label.toUpperCase(), 11, ACCENT, true);
        parent.addView(view);
        return view;
    }

    private void addToggle(LinearLayout parent, String label, boolean checked, String tag, Consumer<Boolean> onChanged) {
        Context c = getContext();
        LinearLayout row = Ui.row(c);
        row.setPadding(Ui.dp(c, 10), Ui.dp(c, 4), Ui.dp(c, 10), Ui.dp(c, 4));
        row.setMinimumHeight(Ui.dp(c, 44));
        Ui.ripple(row, Color.TRANSPARENT, 8);
        TextView name = Ui.text(c, label, 14, INK, false);
        row.addView(name, new LinearLayout.LayoutParams(0, -2, 1));
        Switch toggle = new Switch(c);
        toggle.setChecked(checked);
        toggle.setContentDescription(label);
        toggle.setTag(tag);
        toggle.setThumbTintList(new ColorStateList(new int[][]{{android.R.attr.state_checked}, {}}, new int[]{ACCENT, MUTED}));
        toggle.setTrackTintList(new ColorStateList(new int[][]{{android.R.attr.state_checked}, {}}, new int[]{0x8059a7ff, LINE}));
        toggle.setOnCheckedChangeListener((button, value) -> onChanged.accept(value));
        row.addView(toggle, Ui.lp(c, -2, 32));
        row.setOnClickListener(v -> toggle.setChecked(!toggle.isChecked()));
        parent.addView(row, Ui.lp(c, -1, -2));
    }

    private TextView darkButton(Context c, String label, boolean primary) {
        TextView button = Ui.text(c, label, 14, primary ? Color.WHITE : ACCENT, true);
        Ui.medium(button);
        button.setGravity(Gravity.CENTER);
        button.setMinHeight(Ui.dp(c, 40));
        button.setPadding(Ui.dp(c, primary ? 20 : 16), Ui.dp(c, 8), Ui.dp(c, primary ? 20 : 16), Ui.dp(c, 8));
        Ui.ripple(button, primary ? ACCENT : Color.TRANSPARENT, 24);
        button.setFocusable(true);
        return button;
    }
}
