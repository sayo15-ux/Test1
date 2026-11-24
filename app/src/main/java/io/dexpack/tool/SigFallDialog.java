package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.util.function.Consumer;

final class SigFallDialog extends Dialog {
    private static final int BACKGROUND = 0xff111116;
    private static final int CARD = 0xff1d1d25;
    private static final int FIELD = 0xff272730;
    private static final int LINE = 0xff3f3f4b;
    private static final int ACCENT = 0xffbb86fc;
    private static final int INK = 0xfff5f5f7;
    private static final int MUTED = 0xffb5b5c2;
    private static final int ERROR = 0xffffb4ab;

    private final ProtectionApp app;
    private final SigFallConfig config;
    private TextView status;

    SigFallDialog(Context context, ProtectionApp app) {
        super(context, android.R.style.Theme_Material_Dialog_NoActionBar);
        Ui.registerDialog(context, this);
        this.app = app;
        this.config = SigFallConfig.load(context);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Context c = getContext();
        LinearLayout content = Ui.column(c);
        content.setPadding(Ui.dp(c, 20), Ui.dp(c, 20), Ui.dp(c, 20), Ui.dp(c, 18));

        TextView title = Ui.text(c, "SigFall", 20, INK, true);
        title.setTag("sigFallTitle");
        content.addView(title);
        TextView subtitle = Ui.text(c, "Signature kill v2", 12, MUTED, false);
        Ui.line(subtitle, 17);
        content.addView(subtitle);
        Ui.marginTop(subtitle, 4);

        addToggle(content, "The basics go to sign", config.basicsToSign, "sigFallBasicsToSign", value -> config.basicsToSign = value);

        TextView modeLabel = section(content, "Mode");
        Ui.marginTop(modeLabel, 18);
        String[] modes = {"automatic", "Strength", "High stability"};
        RadioGroup group = new RadioGroup(c);
        group.setOrientation(RadioGroup.HORIZONTAL);
        group.setBackground(Ui.shape(c, CARD, 10));
        group.setPadding(Ui.dp(c, 8), Ui.dp(c, 4), Ui.dp(c, 8), Ui.dp(c, 4));
        int[] ids = new int[modes.length];
        for (int i = 0; i < modes.length; i++) {
            RadioButton option = new RadioButton(c);
            ids[i] = View.generateViewId();
            option.setId(ids[i]);
            option.setText(modes[i]);
            option.setTextSize(13);
            option.setTextColor(INK);
            option.setButtonTintList(ColorStateList.valueOf(ACCENT));
            option.setPadding(Ui.dp(c, 4), Ui.dp(c, 4), Ui.dp(c, 8), Ui.dp(c, 4));
            if (i == 0) option.setTag("sigFallModeAutomatic");
            if (i == 1) option.setTag("sigFallModeStrength");
            if (i == 2) option.setTag("sigFallModeHighStability");
            group.addView(option, new RadioGroup.LayoutParams(0, -2, 1));
        }
        group.check(ids[config.mode]);
        group.setOnCheckedChangeListener((radioGroup, checkedId) -> {
            for (int i = 0; i < ids.length; i++) if (ids[i] == checkedId) config.mode = i;
        });
        content.addView(group, Ui.lp(c, -1, -2));
        Ui.marginTop(group, 8);

        Spinner version = addSpinner(content, "Select a version", SigFallConfig.VERSIONS, config.version, "sigFallVersion");
        version.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                config.version = parent.getItemAtPosition(position).toString();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });
        Spinner redirection = addSpinner(content, "File redirection", SigFallConfig.REDIRECTIONS, config.fileRedirection, "sigFallFileRedirection");
        redirection.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                config.fileRedirection = parent.getItemAtPosition(position).toString();
            }
            @Override public void onNothingSelected(AdapterView<?> parent) { }
        });

        TextView advanced = section(content, "Options");
        Ui.marginTop(advanced, 18);
        addToggle(content, "Resource redirection", config.resourceRedirection, "sigFallResourceRedirection", value -> config.resourceRedirection = value);
        addToggle(content, "Replace the APK path", config.replaceApkPath, "sigFallReplaceApkPath", value -> config.replaceApkPath = value);
        addToggle(content, "Replace the App class name", config.replaceAppClassName, "sigFallReplaceAppClass", value -> config.replaceAppClassName = value);
        addToggle(content, "Enable the Java Hook framework", config.javaHookFramework, "sigFallJavaHookFramework", value -> config.javaHookFramework = value);
        addToggle(content, "Enable maps hiding", config.mapsHiding, "sigFallMapsHiding", value -> config.mapsHiding = value);
        addToggle(content, "Enable DEX obfuscation", config.dexObfuscation, "sigFallDexObfuscation", value -> config.dexObfuscation = value);
        addToggle(content, "Data reuse optimization", config.dataReuseOptimization, "sigFallDataReuse", value -> config.dataReuseOptimization = value);
        addToggle(content, "Debuggable", config.debuggable, "sigFallDebuggable", value -> config.debuggable = value);

        EditText folder = addField(content, "Custom data folder name:", config.dataFolderName, "sigFallDataFolder");
        EditText library = addField(content, "Custom de-check dynamic library name:", config.libraryName, "sigFallLibraryName");

        status = Ui.text(c, "", 12, MUTED, false);
        Ui.line(status, 17);
        content.addView(status);
        Ui.marginTop(status, 12);

        LinearLayout actions = Ui.row(c);
        actions.setGravity(Gravity.END);
        TextView cancel = darkButton(c, "CANCEL", false);
        cancel.setTag("sigFallCancel");
        TextView confirm = darkButton(c, "CONFIRM", true);
        confirm.setTag("sigFallConfirm");
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
            config.dataFolderName = folder.getText().toString();
            config.libraryName = library.getText().toString();
            try {
                config.save(c);
                dismiss();
                SigFallExecutor.apply(app, config, new SigFallExecutor.Listener() {
                    @Override public void onApplied(SigFallConfig value) {
                        Toast.makeText(c, "SigFall configuration applied", Toast.LENGTH_SHORT).show();
                    }
                    @Override public void onError(String message) {
                        Toast.makeText(c, message, Toast.LENGTH_LONG).show();
                    }
                });
            } catch (Exception error) {
                status.setText(error.getMessage() == null ? "Cannot save configuration." : error.getMessage());
                status.setTextColor(ERROR);
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
        Context c = getContext();
        TextView view = Ui.text(c, label.toUpperCase(), 11, ACCENT, true);
        parent.addView(view);
        return view;
    }

    private Switch addToggle(LinearLayout parent, String label, boolean checked, String tag, Consumer<Boolean> onChanged) {
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
        toggle.setThumbTintList(new ColorStateList(
                new int[][]{{android.R.attr.state_checked}, {}},
                new int[]{ACCENT, MUTED}));
        toggle.setTrackTintList(new ColorStateList(
                new int[][]{{android.R.attr.state_checked}, {}},
                new int[]{0x8059a7ff, LINE}));
        toggle.setOnCheckedChangeListener((button, value) -> onChanged.accept(value));
        row.addView(toggle, Ui.lp(c, -2, 32));
        row.setOnClickListener(v -> toggle.setChecked(!toggle.isChecked()));
        parent.addView(row, Ui.lp(c, -1, -2));
        return toggle;
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
        spinner.setSelection(Math.max(0, indexOf(options, selected)));
        spinner.setBackground(Ui.shape(c, FIELD, 8));
        spinner.setPopupBackgroundDrawable(Ui.shape(c, CARD, 8));
        spinner.setContentDescription(label);
        spinner.setTag(tag);
        parent.addView(spinner, Ui.lp(c, -1, 48));
        Ui.marginTop(spinner, 6);
        return spinner;
    }

    private EditText addField(LinearLayout parent, String label, String value, String tag) {
        Context c = getContext();
        TextView name = Ui.text(c, label, 12, MUTED, false);
        parent.addView(name);
        Ui.marginTop(name, 12);
        EditText field = new EditText(c);
        field.setSingleLine();
        field.setText(value);
        field.setTextSize(14);
        field.setTextColor(INK);
        field.setHintTextColor(MUTED);
        field.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        field.setBackground(Ui.shape(c, FIELD, 8));
        field.setPadding(Ui.dp(c, 12), 0, Ui.dp(c, 12), 0);
        field.setContentDescription(label);
        field.setTag(tag);
        parent.addView(field, Ui.lp(c, -1, 48));
        Ui.marginTop(field, 6);
        return field;
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

    private static int indexOf(String[] options, String value) {
        for (int i = 0; i < options.length; i++) if (options[i].equals(value)) return i;
        return 0;
    }
}
