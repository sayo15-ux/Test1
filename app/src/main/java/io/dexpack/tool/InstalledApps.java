package io.dexpack.tool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;

final class InstalledApps extends Dialog {
    private static final class Entry {
        ApplicationInfo app; String label, detail; android.graphics.drawable.Drawable icon;
    }
    private final ExecutorService worker;
    private final FileBrowser.Selected selected;
    private final List<Entry> all = new ArrayList<>(), visible = new ArrayList<>();
    private final Adapter adapter = new Adapter();
    private String query = ""; private boolean reverse;
    InstalledApps(Context c, ExecutorService worker, FileBrowser.Selected selected) { super(c, android.R.style.Theme_Material_Light_NoActionBar); Ui.registerDialog(c, this); this.worker = worker; this.selected = selected; }
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state); Context c = getContext(); LinearLayout page = Ui.column(c);
        LinearLayout bar = Ui.row(c); bar.setPadding(Ui.dp(c, 8), Ui.dp(c, 4), Ui.dp(c, 8), Ui.dp(c, 4));
        Ui.Icon back = Ui.iconButton(c, "back", Ui.INK, "Back"); bar.addView(back, Ui.lp(c, 40, 48)); back.setOnClickListener(v -> dismiss());
        TextView title = Ui.text(c, "Installed apps", 16, Ui.INK, false); Ui.medium(title); LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(0, -2, 1); tp.leftMargin = Ui.dp(c, 4); bar.addView(title, tp);
        Ui.Icon searchButton = Ui.iconButton(c, "search", Ui.INK, "Search apps"), sort = Ui.iconButton(c, "sort", Ui.INK, "Reverse app order"); bar.addView(searchButton, Ui.lp(c, 40, 48)); bar.addView(sort, Ui.lp(c, 40, 48)); page.addView(bar, Ui.lp(c, -1, 56));
        EditText search = new EditText(c); search.setSingleLine(); search.setTextSize(14); search.setTextColor(Ui.INK); search.setHint("Search apps"); search.setPadding(Ui.dp(c, 12), 0, Ui.dp(c, 12), 0); Ui.outline(search, Ui.LINE, 8);
        LinearLayout.LayoutParams sp = Ui.lp(c, -1, 48); sp.setMargins(Ui.dp(c, 12), Ui.dp(c, 8), Ui.dp(c, 12), Ui.dp(c, 8)); page.addView(search, sp); search.setVisibility(View.GONE);
        searchButton.setOnClickListener(v -> { search.setVisibility(search.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE); if (search.getVisibility() == View.GONE) search.setText(""); else search.requestFocus(); }); sort.setOnClickListener(v -> { reverse = !reverse; filter(); });
        TextView status = Ui.text(c, "Loading apps…", 12, Ui.MUTED, false); status.setPadding(Ui.dp(c, 16), Ui.dp(c, 18), Ui.dp(c, 16), Ui.dp(c, 18)); page.addView(status);
        ListView list = new ListView(c); list.setDivider(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT)); list.setDividerHeight(Ui.dp(c, 8)); list.setPadding(Ui.dp(c, 8), Ui.dp(c, 8), Ui.dp(c, 8), Ui.dp(c, 8)); list.setClipToPadding(false); list.setAdapter(adapter); page.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));
        list.setOnItemClickListener((p, v, position, id) -> {
            Entry entry = visible.get(position);
            if (entry.app.splitSourceDirs != null && entry.app.splitSourceDirs.length > 0) { new AlertDialog.Builder(c).setMessage("This application uses split APKs. Select a standalone APK to protect it.").setPositiveButton("OK", null).show(); return; }
            selected.accept(new File(entry.app.sourceDir)); dismiss();
        });
        FrameLayout screen = Ui.centered(c, page); setContentView(screen); Ui.systemBars(getWindow(), screen); Ui.appear(page);
        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            public void onTextChanged(CharSequence s, int start, int before, int count) { query = s.toString().trim().toLowerCase(Locale.ROOT); filter(); }
            public void afterTextChanged(Editable e) { }
        });
        worker.execute(() -> {
            try {
                PackageManager pm = c.getPackageManager(); List<ResolveInfo> resolved = pm.queryIntentActivities(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0); List<Entry> result = new ArrayList<>(); HashSet<String> seen = new HashSet<>();
                for (ResolveInfo info : resolved) if (info.activityInfo != null && seen.add(info.activityInfo.packageName)) {
                    Entry e = new Entry(); e.app = info.activityInfo.applicationInfo; e.label = pm.getApplicationLabel(e.app).toString(); e.icon = pm.getApplicationIcon(e.app);
                    String version = ""; try { PackageInfo p = pm.getPackageInfo(e.app.packageName, 0); version = "\n" + p.versionName + " (" + p.versionCode + ")"; } catch (PackageManager.NameNotFoundException ignored) { }
                    e.detail = e.app.packageName + version + "\n" + String.format(Locale.ROOT, "%.2f MB", new File(e.app.sourceDir).length() / 1048576.0); result.add(e);
                }
                result.sort(Comparator.comparing(e -> e.label, String.CASE_INSENSITIVE_ORDER));
                new Handler(Looper.getMainLooper()).post(() -> { if (isShowing()) { all.clear(); all.addAll(result); filter(); status.setText("No applications found."); status.setVisibility(all.isEmpty() ? View.VISIBLE : View.GONE); } });
            } catch (Exception error) { new Handler(Looper.getMainLooper()).post(() -> status.setText("Could not read installed applications.")); }
        });
    }
    private void filter() { visible.clear(); for (Entry e : all) if (e.label.toLowerCase(Locale.ROOT).contains(query) || e.app.packageName.toLowerCase(Locale.ROOT).contains(query)) visible.add(e); if (reverse) Collections.reverse(visible); adapter.notifyDataSetChanged(); }
    private final class Adapter extends BaseAdapter {
        public int getCount() { return visible.size(); }
        public Object getItem(int p) { return visible.get(p); }
        public long getItemId(int p) { return p; }
        public View getView(int p, View recycled, ViewGroup parent) {
            Context c = parent.getContext(); Entry e = visible.get(p); LinearLayout row = Ui.row(c); row.setMinimumHeight(Ui.dp(c, 70)); row.setPadding(Ui.dp(c, 10), Ui.dp(c, 10), Ui.dp(c, 10), Ui.dp(c, 10)); Ui.ripple(row, Ui.CARD, 10);
            ImageView icon = new ImageView(c); icon.setImageDrawable(e.icon); icon.setScaleType(ImageView.ScaleType.FIT_CENTER); icon.setBackground(Ui.shape(c, Color.WHITE, 8)); icon.setClipToOutline(true); row.addView(icon, Ui.lp(c, 48, 48));
            LinearLayout text = Ui.column(c); TextView name = Ui.text(c, e.label, 14, Ui.INK, false); Ui.medium(name); Ui.line(name, 18); text.addView(name); TextView detail = Ui.text(c, e.detail, 12, Ui.MUTED, false); Ui.line(detail, 15); text.addView(detail);
            LinearLayout.LayoutParams tp = new LinearLayout.LayoutParams(0, -2, 1); tp.leftMargin = Ui.dp(c, 10); row.addView(text, tp); return row;
        }
    }
}
