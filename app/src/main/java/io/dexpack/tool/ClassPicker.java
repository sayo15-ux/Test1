package io.dexpack.tool;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.BaseAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeMap;

final class ClassPicker extends Dialog {
    private static final class Node {
        final String name, descriptor;
        final int depth;
        final TreeMap<String, Node> children = new TreeMap<>();
        final List<String> leaves = new ArrayList<>();
        boolean expanded;
        Node(String name, String descriptor, int depth) { this.name = name; this.descriptor = descriptor; this.depth = depth; }
    }

    private final String[] names;
    private final Set<String> selected;
    private final Set<String> destination;
    private final Runnable saved;
    private final Node root = new Node("", null, -1);
    private final List<Node> rows = new ArrayList<>();
    private final List<String> matching = new ArrayList<>();
    private final Adapter adapter = new Adapter();
    private String query = "";
    private TextView counter, all;
    private final String heading;

    ClassPicker(Context context, String[] names, Set<String> destination, String heading, Runnable saved) {
        super(context, android.R.style.Theme_Material_Light_NoActionBar); Ui.registerDialog(context, this);
        this.heading = heading; this.names = names; this.destination = destination; this.selected = new HashSet<>(destination); this.saved = saved;
        for (String descriptor : names) {
            String display = descriptor.startsWith("L") && descriptor.endsWith(";") ? descriptor.substring(1, descriptor.length() - 1) : descriptor;
            String[] parts = display.split("/");
            Node node = root; node.leaves.add(descriptor);
            for (int i = 0; i < parts.length; i++) {
                boolean leaf = i == parts.length - 1;
                String key = parts[i] + (leaf ? "\u0000" : "/");
                Node next = node.children.get(key);
                if (next == null) { next = new Node(parts[i], leaf ? descriptor : null, i); node.children.put(key, next); }
                next.leaves.add(descriptor); node = next;
            }
        }
    }

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        Context c = getContext();
        LinearLayout page = Ui.column(c); page.setBackgroundColor(Ui.SURFACE);
        LinearLayout bar = Ui.row(c); bar.setPadding(Ui.dp(c, 6), Ui.dp(c, 4), Ui.dp(c, 6), Ui.dp(c, 4));
        Ui.Icon back = Ui.iconButton(c, "back", Ui.INK, "Cancel class selection").size(20); back.setTag("classesBack"); bar.addView(back, Ui.lp(c, 44, 48)); back.setOnClickListener(v -> dismiss());
        LinearLayout title = Ui.column(c); TextView name = Ui.text(c, heading, 18, Ui.INK, false); name.setSingleLine(); name.setEllipsize(android.text.TextUtils.TruncateAt.END); title.addView(name);
        counter = Ui.text(c, "", 10, Ui.MUTED, false); title.addView(counter); bar.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        all = Ui.text(c, "+", 27, Ui.INK, false); all.setTag("classesAll"); all.setGravity(Gravity.CENTER); Ui.ripple(all, Color.TRANSPARENT, 24); all.setFocusable(true); bar.addView(all, Ui.lp(c, 44, 48));
        all.setOnClickListener(v -> { if (selected.size() == names.length) selected.clear(); else java.util.Collections.addAll(selected, names); update(); });
        Ui.Icon save = Ui.iconButton(c, "save", Ui.INK, "Save class selection").size(20); save.setTag("classesSave"); bar.addView(save, Ui.lp(c, 44, 48));
        View.OnClickListener confirm = v -> { destination.clear(); destination.addAll(selected); saved.run(); dismiss(); }; save.setOnClickListener(confirm);
        page.addView(bar, Ui.lp(c, -1, 58));
        EditText search = new EditText(c); search.setTag("classSearch"); search.setSingleLine(true); search.setTextSize(12); search.setHint("Search"); search.setTextColor(Ui.INK); search.setHintTextColor(Ui.MUTED);
        search.setPadding(Ui.dp(c, 8), Ui.dp(c, 10), Ui.dp(c, 8), Ui.dp(c, 10)); Ui.outline(search, Ui.LINE, 4);
        LinearLayout.LayoutParams sp = Ui.lp(c, -1, 40); sp.setMargins(Ui.dp(c, 12), Ui.dp(c, 14), Ui.dp(c, 12), Ui.dp(c, 8)); page.addView(search, sp);
        FrameLayout content = new FrameLayout(c); ListView list = new ListView(c); list.setTag("classTree"); list.setDivider(null); list.setSelector(new android.graphics.drawable.ColorDrawable(Color.TRANSPARENT)); list.setClipToPadding(false); list.setPadding(0, 0, 0, Ui.dp(c, 90)); list.setAdapter(adapter); content.addView(list, new FrameLayout.LayoutParams(-1, -1));
        Ui.Icon done = Ui.iconButton(c, "check", Color.WHITE, "Confirm class selection"); done.setTag("classesDone"); done.setElevation(Ui.dp(c, 5)); Ui.ripple(done, Ui.PURPLE, 13);
        FrameLayout.LayoutParams dp = new FrameLayout.LayoutParams(Ui.dp(c, 48), Ui.dp(c, 48), Gravity.BOTTOM | Gravity.END); dp.setMargins(0, 0, Ui.dp(c, 18), Ui.dp(c, 30)); content.addView(done, dp); done.setOnClickListener(confirm);
        page.addView(content, new LinearLayout.LayoutParams(-1, 0, 1)); FrameLayout screen = Ui.centered(c, page); setContentView(screen); Ui.systemBars(getWindow(), screen); Ui.appear(page);
        if (getWindow() != null) getWindow().setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN | android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) { query = s.toString().trim().toLowerCase(Locale.ROOT).replace('.', '/'); rebuild(); }
            @Override public void afterTextChanged(Editable e) { }
        });
        rebuild();
    }

    private void flatten(Node parent) {
        for (Node child : parent.children.values()) {
            rows.add(child); if (child.expanded) flatten(child);
        }
    }

    private void rebuild() {
        rows.clear(); matching.clear();
        if (query.isEmpty()) { flatten(root); java.util.Collections.addAll(matching, names); }
        else for (String name : names) if (name.toLowerCase(Locale.ROOT).contains(query)) {
            Node n = new Node(name.startsWith("L") ? name.substring(1, name.length() - 1).replace('/', '.') : name, name, 0);
            n.leaves.add(name); rows.add(n); matching.add(name);
        }
        update();
    }

    private void update() {
        if (counter != null) counter.setText(selected.size() + " selected");
        if (all != null) { boolean complete = names.length > 0 && selected.size() == names.length; all.setText(complete ? "−" : "+"); all.setContentDescription(complete ? "Deselect all classes" : "Select all classes"); }
        adapter.notifyDataSetChanged();
    }

    private final class Adapter extends BaseAdapter {
        @Override public int getCount() { return rows.size(); }
        @Override public Object getItem(int position) { return rows.get(position); }
        @Override public long getItemId(int position) { return position; }
        @Override public View getView(int position, View recycled, ViewGroup parent) {
            Context c = parent.getContext(); Node n = rows.get(position);
            LinearLayout row = Ui.row(c); row.setMinimumHeight(Ui.dp(c, 26)); row.setPadding(Ui.dp(c, n.depth * 16), 0, Ui.dp(c, 10), 0);
            TextView expand = Ui.text(c, n.descriptor == null ? "›" : "", 20, 0xff49454f, false); Ui.line(expand, 24); expand.setGravity(Gravity.CENTER); expand.setRotation(n.expanded ? 90 : 0); row.addView(expand, Ui.lp(c, 16, 26));
            expand.setContentDescription((n.expanded ? "Collapse " : "Expand ") + n.name);
            if (n.descriptor == null) expand.setOnClickListener(v -> { n.expanded = !n.expanded; rebuild(); });
            FrameLayout checkTouch = new FrameLayout(c); Ui.Choice check = new Ui.Choice(c, true);
            int chosen = 0; for (String value : n.leaves) if (selected.contains(value)) chosen++;
            check.mixed = chosen > 0 && chosen < n.leaves.size(); check.checked(chosen == n.leaves.size(), false);
            checkTouch.setContentDescription(n.name + ", " + chosen + " of " + n.leaves.size() + " selected"); checkTouch.setFocusable(true);
            checkTouch.addView(check, new FrameLayout.LayoutParams(Ui.dp(c, 18), Ui.dp(c, 18), Gravity.CENTER)); row.addView(checkTouch, Ui.lp(c, 22, 26));
            LinearLayout label = Ui.row(c);
            if (n.descriptor == null) label.addView(new Ui.Icon(c, "folder", 0xff388d89).size(15), Ui.lp(c, 15, 13));
            else { TextView symbol = Ui.text(c, "C", 10, Color.WHITE, true); Ui.line(symbol, 14); symbol.setGravity(Gravity.CENTER); symbol.setBackground(Ui.shape(c, 0xff409886, 7)); label.addView(symbol, Ui.lp(c, 14, 14)); }
            TextView name = Ui.text(c, n.name, 12, Ui.INK, false); Ui.line(name, 18); LinearLayout.LayoutParams np = new LinearLayout.LayoutParams(0, -2, 1); np.leftMargin = Ui.dp(c, 4); label.addView(name, np); label.setMinimumHeight(Ui.dp(c, 26)); row.addView(label, new LinearLayout.LayoutParams(0, -2, 1));
            View.OnClickListener toggle = v -> { if (selected.containsAll(n.leaves)) selected.removeAll(n.leaves); else selected.addAll(n.leaves); update(); };
            checkTouch.setOnClickListener(toggle); label.setOnClickListener(v -> { if (n.descriptor == null) { n.expanded = !n.expanded; rebuild(); } else toggle.onClick(v); });
            return row;
        }
    }
}
