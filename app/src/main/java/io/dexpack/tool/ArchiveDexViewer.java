package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class ArchiveDexViewer extends Dialog {
    private final File apk;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private final List<String> rows = new ArrayList<>();
    private final List<String> all = new ArrayList<>();
    private final BaseAdapter adapter = new BaseAdapter() {
        @Override public int getCount() { return rows.size(); }
        @Override public Object getItem(int position) { return rows.get(position); }
        @Override public long getItemId(int position) { return position; }
        @Override public android.view.View getView(int position, android.view.View convertView, ViewGroup parent) {
            Context c = parent.getContext();
            LinearLayout row = Ui.row(c);
            row.setPadding(Ui.dp(c,12), Ui.dp(c,8), Ui.dp(c,12), Ui.dp(c,8));
            TextView t = Ui.text(c, rows.get(position), 11, Ui.INK, false);
            t.setSingleLine(false);
            row.addView(t, new LinearLayout.LayoutParams(-1, -2));
            return row;
        }
    };
    private TextView status;
    private EditText search;
    private boolean archiveMode = true;
    private Runnable pending;

    ArchiveDexViewer(Context context, File apk) {
        super(context, android.R.style.Theme_Material_Light_NoActionBar);
        Ui.registerDialog(context, this);
        this.apk = apk;
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Context c = getContext();
        LinearLayout page = Ui.column(c); page.setBackgroundColor(Ui.SURFACE);
        LinearLayout bar = Ui.row(c); bar.setPadding(Ui.dp(c,6),Ui.dp(c,4),Ui.dp(c,6),Ui.dp(c,4));
        Ui.Icon back = Ui.iconButton(c, "back", Ui.INK, "Close viewer").size(20); back.setOnClickListener(v -> dismiss());
        bar.addView(back, Ui.lp(c,44,48));
        TextView title = Ui.text(c, "APK/DEX Viewer", 18, Ui.INK, false); bar.addView(title, new LinearLayout.LayoutParams(0,-2,1));
        TextView mode = Ui.text(c, "DEX", 12, Ui.PURPLE, true); mode.setPadding(Ui.dp(c,10),Ui.dp(c,6),Ui.dp(c,10),Ui.dp(c,6)); Ui.outline(mode, Ui.PURPLE, 12);
        mode.setOnClickListener(v -> { archiveMode = !archiveMode; mode.setText(archiveMode?"DEX":"ARCHIVE"); load(""); search.setText(""); });
        bar.addView(mode, Ui.lp(c,-2,-2));
        page.addView(bar, Ui.lp(c,-1,58));

        search = new EditText(c); search.setHint(archiveMode?"Filter entries":"Search class/method/string"); search.setSingleLine(true);
        search.setPadding(Ui.dp(c,10),Ui.dp(c,10),Ui.dp(c,10),Ui.dp(c,10)); Ui.outline(search, Ui.LINE, 4);
        LinearLayout.LayoutParams sp = Ui.lp(c,-1,42); sp.setMargins(Ui.dp(c,12),Ui.dp(c,8),Ui.dp(c,12),Ui.dp(c,8)); page.addView(search, sp);
        status = Ui.text(c, "Loading...", 12, Ui.MUTED, false); status.setPadding(Ui.dp(c,12),0,Ui.dp(c,12),Ui.dp(c,8)); page.addView(status, Ui.lp(c,-1,-2));
        ListView list = new ListView(c); list.setAdapter(adapter); list.setDivider(null); page.addView(list, new LinearLayout.LayoutParams(-1,0,1));
        android.widget.FrameLayout screen = Ui.centered(c, page);
        setContentView(screen);
        Ui.systemBars(getWindow(), screen);

        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                String q = s.toString().trim();
                if (archiveMode) filter(q);
                else {
                    if (pending != null) ui.removeCallbacks(pending);
                    pending = () -> load(q);
                    ui.postDelayed(pending, 350);
                }
            }
            @Override public void afterTextChanged(Editable s) {}
        });
        load("");
    }

    private void load(String q) {
        status.setText("Loading...");
        worker.execute(() -> {
            try {
                String[] result = archiveMode ? NativeEngine.archiveEntries(apk.getAbsolutePath()) : NativeEngine.dexSearch(apk.getAbsolutePath(), q);
                List<String> next = new ArrayList<>();
                if (result != null) for (String r : result) next.add(format(r));
                ui.post(() -> { all.clear(); all.addAll(next); rows.clear(); rows.addAll(next); status.setText(rows.size() + " items"); adapter.notifyDataSetChanged(); });
            } catch (Exception e) {
                ui.post(() -> status.setText("Error: " + e.getMessage()));
            }
        });
    }

    private void filter(String q) {
        String lq = q.toLowerCase(Locale.ROOT);
        rows.clear();
        for (String s : all) if (lq.isEmpty() || s.toLowerCase(Locale.ROOT).contains(lq)) rows.add(s);
        status.setText(rows.size() + " items");
        adapter.notifyDataSetChanged();
    }

    private String format(String r) {
        String[] p = r.split("\\|", -1);
        if (archiveMode && p.length >= 4) return p[3] + "  " + p[0] + "  (" + p[2] + "B)";
        if (!archiveMode && p.length >= 5) {
            if ("class".equals(p[1])) return "["+p[0]+"] class " + p[2];
            if ("method".equals(p[1])) return "["+p[0]+"] " + p[2] + " -> " + p[3];
            if ("string".equals(p[1])) return "["+p[0]+"] " + p[2]+"."+p[3]+" : \""+p[4]+"\"";
        }
        return r;
    }

    @Override public void dismiss() { super.dismiss(); worker.shutdownNow(); }
}
