package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;

import java.util.function.Consumer;

final class SignatureKillV3Dialog extends Dialog {
    private static final int BACKGROUND = 0xff111116;
    private static final int CARD = 0xff1d1d25;
    private static final int FIELD = 0xff272730;
    private static final int LINE = 0xff3f3f4b;
    private static final int ACCENT = 0xffbb86fc;
    private static final int INK = 0xfff5f5f7;
    private static final int MUTED = 0xffb5b5c2;

    private final ProtectionApp app;

    SignatureKillV3Dialog(Context context, ProtectionApp app) {
        super(context, android.R.style.Theme_Material_Dialog_NoActionBar);
        Ui.registerDialog(context, this);
        this.app = app;
        requestWindowFeature(Window.FEATURE_NO_TITLE);
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Context c = getContext();
        SignatureKillV3Config config = SignatureKillV3Config.load(c);
        LinearLayout content = Ui.column(c);
        content.setPadding(Ui.dp(c, 20), Ui.dp(c, 20), Ui.dp(c, 20), Ui.dp(c, 18));

        TextView title = Ui.text(c, "Signature Kill v3", 20, INK, true);
        title.setTag("sigKillV3Title");
        content.addView(title);
        TextView subtitle = Ui.text(c, "Transparent fallback options (no stealth/maps hiding)", 12, MUTED, false);
        Ui.line(subtitle, 17);
        content.addView(subtitle);
        Ui.marginTop(subtitle, 4);

        TextView modeLabel = section(content, "Options");
        Ui.marginTop(modeLabel, 18);
        addToggle(content, "PackageManager proxy", config.pmProxy, "sigKillV3PmProxy", v -> config.pmProxy = v);
        addToggle(content, "Early ContentProvider init", config.earlyProvider, "sigKillV3EarlyProvider", v -> config.earlyProvider = v);
        addToggle(content, "Patch SigningInfo reflection", config.patchSigningInfo, "sigKillV3SigningInfo", v -> config.patchSigningInfo = v);
        addToggle(content, "Replace APK path", config.replaceApkPath, "sigKillV3ReplacePath", v -> config.replaceApkPath = v);
        addToggle(content, "Patch ApplicationInfo paths", config.patchApplicationInfo, "sigKillV3ApplicationInfo", v -> config.patchApplicationInfo = v);
        addToggle(content, "Basics go to sign", config.basicsToSign, "sigKillV3BasicsSign", v -> config.basicsToSign = v);
        addToggle(content, "Debuggable manifest flag", config.debuggable, "sigKillV3Debuggable", v -> config.debuggable = v);

        Spinner version = addSpinner(content, "Select a version", SignatureKillV3Config.VERSIONS, config.version, "sigKillV3Version");
        version.setOnItemSelectedListener(new SimpleSelect(v -> config.version = v));
        Spinner redirection = addSpinner(content, "File redirection", SignatureKillV3Config.REDIRECTIONS, config.fileRedirection, "sigKillV3FileRedirection");
        redirection.setOnItemSelectedListener(new SimpleSelect(v -> config.fileRedirection = v));

        LinearLayout actions = Ui.row(c);
        actions.setGravity(Gravity.END);
        TextView cancel = darkButton(c, "CANCEL", false);
        cancel.setTag("sigKillV3Cancel");
        TextView confirm = darkButton(c, "SAVE", true);
        confirm.setTag("sigKillV3Confirm");
        actions.addView(cancel, Ui.lp(c, -2, 40));
        LinearLayout.LayoutParams confirmParams = Ui.lp(c, -2, 40);
        confirmParams.leftMargin = Ui.dp(c, 10);
        actions.addView(confirm, confirmParams);
        content.addView(actions, Ui.lp(c, -1, -2));
        Ui.marginTop(actions, 16);

        cancel.setOnClickListener(v -> dismiss());
        confirm.setOnClickListener(v -> {
            config.version = version.getSelectedItem().toString();
            config.fileRedirection = redirection.getSelectedItem().toString();
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

    private Spinner addSpinner(LinearLayout parent, String label, String[] options, String selected, String tag) {
        Context c = getContext();
        TextView name = Ui.text(c, label, 12, MUTED, false);
        parent.addView(name);
        Spinner spinner = new Spinner(c, Spinner.MODE_DROPDOWN);
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(c, android.R.layout.simple_spinner_item, options) {
            @Override public View getView(int position, View convertView, ViewGroup parentView) {
                View view = super.getView(position, convertView, parentView);
                if (view instanceof TextView) ((TextView) view).setTextColor(INK);
                return view;
            }
            @Override public View getDropDownView(int position, View convertView, ViewGroup parentView) {
                View view = super.getDropDownView(position, convertView, parentView);
                if (view instanceof TextView) ((TextView) view).setTextColor(INK);
                return view;
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
        for (int i = 0; i < options.length; i++) if (options[i].equals(selected)) { spinner.setSelection(i); break; }
        spinner.setBackground(Ui.shape(c, FIELD, 8));
        spinner.setPopupBackgroundDrawable(Ui.shape(c, CARD, 8));
        spinner.setContentDescription(label);
        spinner.setTag(tag);
        parent.addView(spinner, Ui.lp(c, -1, 48));
        Ui.marginTop(spinner, 6);
        return spinner;
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

    private static final class SimpleSelect implements AdapterView.OnItemSelectedListener {
        private final Consumer<String> onSelected;
        SimpleSelect(Consumer<String> onSelected) { this.onSelected = onSelected; }
        @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) { onSelected.accept(parent.getItemAtPosition(position).toString()); }
        @Override public void onNothingSelected(AdapterView<?> parent) { }
    }
}
