package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.TextView;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;

final class FileBrowser extends Dialog {
    interface Selected { void accept(File file); }
    private final Selected selected;
    private final Runnable systemPicker;
    private final List<File> entries = new ArrayList<>();
    private File folder = Environment.getExternalStorageDirectory();
    private TextView path, status;
    private final Adapter adapter = new Adapter();
    FileBrowser(Context context, Selected selected, Runnable systemPicker) { super(context, android.R.style.Theme_Material_Light_NoActionBar); Ui.registerDialog(context, this); this.selected = selected; this.systemPicker = systemPicker; }
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state); Context c = getContext(); LinearLayout root = Ui.column(c);
        LinearLayout bar = Ui.row(c); bar.setPadding(Ui.dp(c, 4), Ui.dp(c, 4), Ui.dp(c, 4), Ui.dp(c, 4));
        Ui.Icon back = Ui.iconButton(c, "back", 0xff49454f, "Back").size(22); LinearLayout.LayoutParams bp = Ui.lp(c, 40, 48); bp.rightMargin = Ui.dp(c, 4); bar.addView(back, bp); back.setOnClickListener(v -> onBackPressed());
        LinearLayout heading = Ui.column(c); heading.addView(Ui.text(c, "Select file", 20, Ui.INK, false)); path = Ui.text(c, "", 10, Ui.INK, false); path.setMaxLines(1); path.setEllipsize(android.text.TextUtils.TruncateAt.END); heading.addView(path); LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(0, -2, 1); hp.leftMargin = Ui.dp(c, 4); bar.addView(heading, hp);
        Ui.Icon home = Ui.iconButton(c, "home", 0xff49454f, "Storage home").size(22), more = Ui.iconButton(c, "more", 0xff49454f, "File browser menu").size(22);
        bar.addView(home, Ui.lp(c, 40, 48)); bar.addView(more, Ui.lp(c, 40, 48)); home.setOnClickListener(v -> open(Environment.getExternalStorageDirectory()));
        more.setOnClickListener(v -> {
            TextView choice = Ui.button(c, "Use system file picker", false); choice.setTextColor(Ui.INK); choice.setBackground(Ui.shape(c, Ui.SURFACE, 4));
            PopupWindow popup = new PopupWindow(choice, Ui.dp(c, 216), Ui.dp(c, 48), true); popup.setBackgroundDrawable(Ui.shape(c, Ui.SURFACE, 4)); popup.setElevation(Ui.dp(c, 6));
            choice.setOnClickListener(item -> { popup.dismiss(); dismiss(); systemPicker.run(); }); popup.showAsDropDown(more, -Ui.dp(c, 176), 0);
        });
        root.addView(bar, Ui.lp(c, -1, 56));
        status = Ui.text(c, "", 12, Ui.MUTED, false); status.setPadding(Ui.dp(c, 16), Ui.dp(c, 18), Ui.dp(c, 16), Ui.dp(c, 18)); root.addView(status);
        ListView list = new ListView(c); list.setDivider(null); list.setPadding(Ui.dp(c, 8), Ui.dp(c, 4), Ui.dp(c, 8), Ui.dp(c, 20)); list.setClipToPadding(false); list.setAdapter(adapter); root.addView(list, new LinearLayout.LayoutParams(-1, 0, 1));
        list.setOnItemClickListener((p, v, position, id) -> { File file = entries.get(position); if (file.isDirectory()) open(file); else { selected.accept(file); dismiss(); } });
        FrameLayout screen = Ui.centered(c, root); setContentView(screen); Ui.systemBars(getWindow(), screen); Ui.appear(root); open(folder);
    }
    @Override public void onBackPressed() { File parent = folder.getParentFile(); if (!folder.equals(Environment.getExternalStorageDirectory()) && parent != null && parent.canRead()) open(parent); else dismiss(); }
    private void open(File directory) {
        folder = directory; path.setText(folder.getAbsolutePath()); entries.clear();
        File parent = folder.getParentFile(); if (parent != null && parent.canRead() && !folder.equals(Environment.getExternalStorageDirectory())) entries.add(parent);
        File[] files = directory.listFiles(file -> file.isDirectory() || file.getName().toLowerCase(Locale.ROOT).endsWith(".apk"));
        if (files != null) { Arrays.sort(files, Comparator.comparing((File f) -> !f.isDirectory()).thenComparing(f -> f.getName().toLowerCase(Locale.ROOT))); entries.addAll(Arrays.asList(files)); }
        status.setText(files == null ? "This folder is not accessible. Use the system file picker from the menu." : "No APKs or folders found."); status.setVisibility(files == null || entries.isEmpty() ? View.VISIBLE : View.GONE); adapter.notifyDataSetChanged();
    }
    private final class Adapter extends BaseAdapter {
        public int getCount() { return entries.size(); }
        public Object getItem(int p) { return entries.get(p); }
        public long getItemId(int p) { return p; }
        public View getView(int position, View recycled, ViewGroup parent) {
            File file = entries.get(position); boolean up = file.equals(folder.getParentFile()); Context c = parent.getContext(); LinearLayout row = Ui.row(c); row.setPadding(Ui.dp(c, 8), Ui.dp(c, 8), Ui.dp(c, 8), Ui.dp(c, 8)); row.setMinimumHeight(Ui.dp(c, up ? 48 : 56)); Ui.ripple(row, Color.TRANSPARENT, 4); if (up) row.setAlpha(.52f);
            Ui.Icon icon = new Ui.Icon(c, file.isDirectory() ? "folder" : "android", file.isDirectory() ? Ui.PURPLE : 0xff7cb342).size(file.isDirectory() ? 32 : 26);
            if (!file.isDirectory()) icon.setBackground(Ui.shape(c, Color.WHITE, 4)); row.addView(icon, Ui.lp(c, 32, file.isDirectory() ? 28 : 32));
            LinearLayout copy = Ui.column(c); TextView name = Ui.text(c, up ? "…" : file.getName(), 14, 0xff49454f, false); Ui.line(name, 18); copy.addView(name);
            if (!up) { String date = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.ROOT).format(new Date(file.lastModified())); String meta = file.isDirectory() ? date : String.format(Locale.ROOT, "%.2f MB · %s", file.length() / 1048576.0, date); TextView detail = Ui.text(c, meta, 10, Ui.MUTED, false); detail.setLetterSpacing(.015f); copy.addView(detail); }
            LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(0, -2, 1); cp.leftMargin = Ui.dp(c, 12); row.addView(copy, cp); return row;
        }
    }
}
