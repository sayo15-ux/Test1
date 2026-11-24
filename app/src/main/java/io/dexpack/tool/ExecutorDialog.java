package io.dexpack.tool;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Typeface;
import android.text.SpannableString;
import android.text.Selection;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

final class ExecutorDialog {
    private final Ui.Sheet dialog;
    private final ProtectionApp app;
    private final StepIcon[] icons = new StepIcon[4];
    private final Track[] tracks = new Track[4];
    private final TextView[] percentages = new TextView[4];
    private final TextView status, path, close, log;
    private final LinearLayout content;
    ExecutorDialog(Context c, ProtectionApp app) {
        this.app = app; content = Ui.column(c); content.setPadding(Ui.dp(c, 18), Ui.dp(c, 20), Ui.dp(c, 18), Ui.dp(c, 14));
        TextView title = Ui.text(c, "Feature Executor", 16, Ui.INK, true); title.setLetterSpacing(.15f / 16); content.addView(title);
        String[] labels = {"Preparing…", "Analyzing DEX…", "Building DEX…", "Building APK…"};
        for (int i = 0; i < 4; i++) {
            LinearLayout step = Ui.column(c), heading = Ui.row(c); icons[i] = new StepIcon(c); heading.addView(icons[i], Ui.lp(c, 22, 22));
            TextView label = Ui.text(c, labels[i], 14, Ui.INK, false); Ui.medium(label); LinearLayout.LayoutParams lp = Ui.lp(c, -1, -2); lp.leftMargin = Ui.dp(c, 14); heading.addView(label, lp); step.addView(heading, Ui.lp(c, -1, 22));
            LinearLayout progress = Ui.row(c); tracks[i] = new Track(c); progress.addView(tracks[i], new LinearLayout.LayoutParams(0, Ui.dp(c, 6), 1));
            percentages[i] = Ui.text(c, "0%", 12, Ui.INK, false); Ui.medium(percentages[i]); percentages[i].setGravity(Gravity.END); LinearLayout.LayoutParams pp = Ui.lp(c, 32, -2); pp.leftMargin = Ui.dp(c, 4); progress.addView(percentages[i], pp);
            LinearLayout.LayoutParams rp = Ui.lp(c, -1, -2); rp.leftMargin = Ui.dp(c, 36); rp.topMargin = Ui.dp(c, 10); step.addView(progress, rp); content.addView(step, Ui.lp(c, -1, -2)); Ui.marginTop(step, i == 0 ? 14 : 22);
        }
        status = Ui.text(c, "", 16, Ui.PURPLE, false); Ui.medium(status); Ui.line(status, 23); status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE); content.addView(status); Ui.marginTop(status, 20);
        log = Ui.text(c, "$ waiting for output…", 11, Ui.TERMINAL_FG, false); log.setTypeface(Typeface.MONOSPACE); Ui.line(log, 16); log.setBackground(Ui.shape(c, Ui.TERMINAL_BG, 8)); log.setPadding(Ui.dp(c, 12), Ui.dp(c, 10), Ui.dp(c, 12), Ui.dp(c, 10)); log.setMinHeight(Ui.dp(c, 110)); log.setMaxLines(9); log.setTextIsSelectable(true); log.setMovementMethod(new ScrollingMovementMethod()); log.setTag("executorLog"); log.setOnTouchListener((v, event) -> { v.getParent().requestDisallowInterceptTouchEvent(true); return false; }); content.addView(log, Ui.lp(c, -1, -2)); Ui.marginTop(log, 12);
        path = Ui.text(c, "", 12, Ui.MUTED, false); Ui.line(path, 17); path.setTextIsSelectable(true); content.addView(path); Ui.marginTop(path, 20);
        LinearLayout actions = Ui.row(c); actions.setGravity(Gravity.END);
        TextView copy = Ui.button(c, "Copy Log", false); copy.setTag("copyLog");
        copy.setOnClickListener(v -> {
            android.content.ClipboardManager cm = (android.content.ClipboardManager) c.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) { cm.setPrimaryClip(android.content.ClipData.newPlainText("DexPack log", log.getText().toString())); android.widget.Toast.makeText(c, "Log copied", android.widget.Toast.LENGTH_SHORT).show(); }
        });
        actions.addView(copy, Ui.lp(c, -2, 40));
        close = Ui.button(c, "Close", false);
        LinearLayout.LayoutParams closeLp = Ui.lp(c, -2, 40); closeLp.leftMargin = Ui.dp(c, 8); actions.addView(close, closeLp);
        content.addView(actions, Ui.lp(c, -1, -2)); Ui.marginTop(actions, 24);
        dialog = new Ui.Sheet(c, content, false); close.setOnClickListener(v -> dialog.dismiss());
    }
    void show() { dialog.show(); }
    boolean isShowing() { return dialog.isShowing(); }
    void dismissImmediately() { dialog.dismissImmediately(); }
    void update() {
        int p = Math.max(0, Math.min(100, app.percent));
        int active = p < 5 ? 0 : p < 15 ? 1 : p < 70 ? 2 : 3;
        int[] boundaries = {0, 5, 15, 70, 100};
        for (int i = 0; i < 4; i++) {
            int value = p >= boundaries[i + 1] ? 100 : p <= boundaries[i] ? 0 : (p - boundaries[i]) * 100 / (boundaries[i + 1] - boundaries[i]);
            tracks[i].progress(value); percentages[i].setText(value + "%");
            icons[i].state(value == 100 ? 2 : i == active && app.failed ? 3 : i == active && app.processing ? 1 : 0);
        }
        boolean finished = app.saved != null;
        status.setText(finished ? "Processing completed" : app.status); status.setTextColor(app.failed ? Ui.ERROR : Ui.PURPLE); status.setTextSize(app.failed ? 14 : 16); Ui.line(status, app.failed ? 20 : 23);
        renderLog();
        path.setText(finished ? app.saved.path : ""); path.setVisibility(finished ? View.VISIBLE : View.GONE);
        close.setEnabled(!app.processing); close.setAlpha(app.processing ? .4f : 1); dialog.setCancelable(!app.processing); dialog.setCanceledOnTouchOutside(!app.processing);
    }
    private void renderLog() {
        StringBuilder builder = new StringBuilder();
        for (String line : app.log) {
            if (builder.length() > 0) builder.append('\n');
            builder.append(line);
        }
        String value = builder.length() == 0 ? "$ waiting for output…" : builder.toString();
        if (!value.equals(log.getText().toString())) {
            SpannableString text = new SpannableString(value);
            Selection.setSelection(text, text.length());
            log.setText(text);
        }
    }

    private static final class Track extends View {
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        float amount; ValueAnimator animator;
        Track(Context c) { super(c); }
        void progress(int value) {
            if (Math.abs(amount - value) < .1f) return;
            if (animator != null) animator.cancel();
            if (!ValueAnimator.areAnimatorsEnabled()) { amount = value; invalidate(); return; }
            animator = ValueAnimator.ofFloat(amount, value); animator.setDuration(240); animator.setInterpolator(Ui.MOTION); animator.addUpdateListener(a -> { amount = (float) a.getAnimatedValue(); invalidate(); }); animator.start();
        }
        @Override protected void onDetachedFromWindow() { if (animator != null) animator.cancel(); super.onDetachedFromWindow(); }
        @Override protected void onDraw(Canvas c) { paint.setColor(0xffded5e8); c.drawRoundRect(0, 0, getWidth(), getHeight(), getHeight() / 2f, getHeight() / 2f, paint); paint.setColor(Ui.PURPLE); c.drawRoundRect(0, 0, getWidth() * amount / 100, getHeight(), getHeight() / 2f, getHeight() / 2f, paint); }
    }
    private static final class StepIcon extends View {
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        final Path path = new Path();
        int state = -1;
        StepIcon(Context c) { super(c); }
        void state(int value) { if (state != value) { state = value; invalidate(); } }
        @Override protected void onDraw(Canvas c) {
            float cx = getWidth() / 2f, cy = getHeight() / 2f, r = Math.min(cx, cy);
            paint.setStyle(Paint.Style.FILL); paint.setColor(state == 2 ? Ui.PURPLE : state == 3 ? Ui.ERROR : Ui.LINE);
            if (state == 1) {
                float stroke = Ui.dp(getContext(), 2); paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(stroke); paint.setColor(0xffd9cdea); c.drawCircle(cx, cy, r - stroke / 2, paint);
                paint.setColor(Ui.PURPLE); float angle = ValueAnimator.areAnimatorsEnabled() ? android.os.SystemClock.uptimeMillis() % 900 * .4f : -90;
                c.drawArc(stroke / 2, stroke / 2, getWidth() - stroke / 2, getHeight() - stroke / 2, angle, 90, false, paint); if (ValueAnimator.areAnimatorsEnabled()) postInvalidateOnAnimation();
            } else {
                c.drawCircle(cx, cy, r, paint);
                if (state == 2) { paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(Ui.dp(getContext(), 2)); paint.setColor(0xffffffff); paint.setStrokeCap(Paint.Cap.ROUND); paint.setStrokeJoin(Paint.Join.ROUND); Path p = path; p.reset(); p.moveTo(cx-r*.5f, cy); p.lineTo(cx-r*.12f, cy+r*.35f); p.lineTo(cx+r*.55f, cy-r*.4f); c.drawPath(p, paint); }
                if (state == 3) { paint.setColor(0xffffffff); paint.setTextSize(Ui.dp(getContext(), 15)); paint.setTextAlign(Paint.Align.CENTER); c.drawText("!", cx, cy + Ui.dp(getContext(), 5), paint); }
            }
        }
    }
}
