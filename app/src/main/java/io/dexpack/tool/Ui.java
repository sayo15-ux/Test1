package io.dexpack.tool;

import android.animation.ValueAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.LineHeightSpan;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.PathInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

final class Ui {
    static boolean dark = true;
    static int SURFACE, CARD, SELECTED, PURPLE, INK, MUTED, ERROR, LINE, GLOW, TERMINAL_BG, TERMINAL_FG, CARD_STROKE;
    static final PathInterpolator MOTION = new PathInterpolator(.2f, 0, 0, 1);
    static { palette(); }
    private Ui() { }
    static void apply(Context c) { dark = c.getSharedPreferences("ui", 0).getBoolean("dark", true); palette(); }
    static void toggle(Context c) { dark = !dark; c.getSharedPreferences("ui", 0).edit().putBoolean("dark", dark).apply(); palette(); }
    static void palette() {
        if (dark) {
            SURFACE=0xff0b1020; CARD=0xff141b2d; SELECTED=0xff1f2b46; PURPLE=0xff6cf2ff; INK=0xffe8edf7; MUTED=0xff8a93a6;
            ERROR=0xffff5c7a; LINE=0xff26324a; GLOW=0x336cf2ff; TERMINAL_BG=0xff09101d; TERMINAL_FG=0xff8ff7c8; CARD_STROKE=0xff2b3a59;
        } else {
            SURFACE=0xfff4f7fb; CARD=0xffe9eef7; SELECTED=0xffdce7fb; PURPLE=0xff4f6bff; INK=0xff141b2d; MUTED=0xff5f6b7a;
            ERROR=0xffd83a56; LINE=0xffcfd8e6; GLOW=0x224f6bff; TERMINAL_BG=0xff141b2d; TERMINAL_FG=0xffb7f7c2; CARD_STROKE=0xffc8d5ea;
        }
    }
    static int dp(Context c, float value) { return Math.round(value * c.getResources().getDisplayMetrics().density); }
    static GradientDrawable shape(Context c, int color, float radius) {
        GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(c, radius)); return d;
    }
    static GradientDrawable cardShape(Context c, float radius) {
        GradientDrawable d = shape(c, CARD, radius); d.setStroke(dp(c, 1), CARD_STROKE); return d;
    }
    static void ripple(View view, int color, float radius) {
        Context c = view.getContext();
        int rippleColor = dark ? 0x446cf2ff : 0x334f6bff;
        view.setBackground(new RippleDrawable(ColorStateList.valueOf(rippleColor), shape(c, color, radius), shape(c, Color.WHITE, radius)));
    }
    static void outline(View view, int color, float radius) {
        Context c = view.getContext(); GradientDrawable border = shape(c, Color.TRANSPARENT, radius);
        border.setStroke(dp(c, 1), color);
        int rippleColor = dark ? 0x336cf2ff : 0x224f6bff;
        view.setBackground(new RippleDrawable(ColorStateList.valueOf(rippleColor), border, shape(c, Color.WHITE, radius)));
    }
    static TextView text(Context c, String label, float size, int color, boolean bold) {
        LineText t = new LineText(c); t.setTextSize(size); t.setTextColor(color);
        t.setTypeface(Typeface.create("sans-serif", bold ? Typeface.BOLD : Typeface.NORMAL));
        t.setIncludeFontPadding(false); t.setBreakStrategy(android.graphics.text.LineBreaker.BREAK_STRATEGY_SIMPLE);
        int height = size <= 11 ? 14 : size <= 12 ? 16 : size <= 14 ? 20 : (int) size + 6;
        t.lineHeight = Math.round(height * c.getResources().getDisplayMetrics().scaledDensity);
        t.setText(label); return t;
    }
    static void line(TextView text, float height) {
        if (text instanceof LineText) {
            ((LineText) text).lineHeight = Math.round(height * text.getResources().getDisplayMetrics().scaledDensity);
            text.setText(text.getText());
        }
    }
    static void medium(TextView t) { t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL)); }
    static LinearLayout column(Context c) { LinearLayout l = new LinearLayout(c); l.setOrientation(LinearLayout.VERTICAL); return l; }
    static LinearLayout row(Context c) { LinearLayout l = new LinearLayout(c); l.setOrientation(LinearLayout.HORIZONTAL); l.setGravity(Gravity.CENTER_VERTICAL); return l; }
    static LinearLayout flow(Context c) { return new FlowRow(c); }
    static LinearLayout.LayoutParams lp(Context c, int width, int height) {
        return new LinearLayout.LayoutParams(width < 0 ? width : dp(c, width), height < 0 ? height : dp(c, height));
    }
    static void marginTop(View v, int value) { LinearLayout.LayoutParams p = (LinearLayout.LayoutParams) v.getLayoutParams(); p.topMargin = dp(v.getContext(), value); v.setLayoutParams(p); }
    static TextView button(Context c, String label, boolean primary) {
        TextView t = text(c, label, 14, primary ? Color.WHITE : PURPLE, false); medium(t);
        t.setGravity(Gravity.CENTER); t.setMinHeight(dp(c, 40)); t.setPadding(dp(c, primary ? 20 : 12), dp(c, 8), dp(c, primary ? 20 : 12), dp(c, 8));
        ripple(t, primary ? PURPLE : Color.TRANSPARENT, 24); t.setFocusable(true); return t;
    }
    static TextView badge(Context c, String label, boolean outlined) {
        TextView t = text(c, label, 11, outlined ? PURPLE : 0xff21005d, true); line(t, 14);
        t.setPadding(dp(c, outlined ? 4 : 6), dp(c, outlined ? 0 : 1), dp(c, outlined ? 4 : 6), dp(c, outlined ? 0 : 1));
        GradientDrawable background = shape(c, outlined ? Color.TRANSPARENT : 0xffedddff, outlined ? 4 : 10);
        if (outlined) background.setStroke(dp(c, 1), PURPLE); t.setBackground(background); return t;
    }
    static Icon iconButton(Context c, String kind, int color, String description) {
        Icon v = new Icon(c, kind, color); v.setContentDescription(description); v.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES); v.setFocusable(true); ripple(v, Color.TRANSPARENT, 24); return v;
    }
    static void registerDialog(Context context, Dialog dialog) { if (context instanceof MainActivity) ((MainActivity) context).trackDialog(dialog); }
    static void systemBars(Window window, View page) {
        if (window == null) return;
        window.setStatusBarColor(SURFACE); window.setNavigationBarColor(SURFACE);
        int flags = 0;
        if (!dark) {
            flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
            flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        }
        window.getDecorView().setSystemUiVisibility(flags);
        if (Build.VERSION.SDK_INT >= 35) {
            page.setOnApplyWindowInsetsListener((v, i) -> {
                v.setPadding(i.getSystemWindowInsetLeft(), i.getSystemWindowInsetTop(), i.getSystemWindowInsetRight(), i.getSystemWindowInsetBottom()); return i;
            });
        }
    }
    static FrameLayout centered(Context c, View page) {
        FrameLayout outer = new FrameLayout(c) {
            @Override protected void onMeasure(int w, int h) {
                int available = MeasureSpec.getSize(w) - getPaddingLeft() - getPaddingRight();
                getChildAt(0).getLayoutParams().width = Math.min(dp(getContext(), 640), available);
                super.onMeasure(w, h);
            }
        };
        outer.setBackgroundColor(SURFACE);
        outer.addView(page, new FrameLayout.LayoutParams(-1, -1, Gravity.TOP | Gravity.CENTER_HORIZONTAL)); return outer;
    }
    static void appear(View v) {
        if (!ValueAnimator.areAnimatorsEnabled()) return;
        v.setAlpha(0); v.animate().alpha(1).setDuration(180).setInterpolator(MOTION).start();
    }

    private static final class FlowRow extends LinearLayout {
        FlowRow(Context c) { super(c); }
        @Override protected void onMeasure(int widthSpec, int heightSpec) {
            int available = MeasureSpec.getSize(widthSpec), x = 0, y = 0, line = 0, widest = 0;
            for (int i = 0; i < getChildCount(); i++) {
                View child = getChildAt(i); if (child.getVisibility() == GONE) continue;
                measureChildWithMargins(child, widthSpec, 0, heightSpec, 0);
                LayoutParams p = (LayoutParams) child.getLayoutParams(); int width = child.getMeasuredWidth() + p.leftMargin + p.rightMargin;
                if (x > 0 && x + width > available) { widest = Math.max(widest, x); y += line; x = 0; line = 0; }
                x += width; line = Math.max(line, child.getMeasuredHeight());
            }
            setMeasuredDimension(resolveSize(Math.max(widest, x), widthSpec), resolveSize(y + line, heightSpec));
        }
        @Override protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            int x = 0, y = 0, line = 0, start = 0;
            for (int i = 0; i <= getChildCount(); i++) {
                View child = i < getChildCount() ? getChildAt(i) : null;
                LayoutParams p = child == null ? null : (LayoutParams) child.getLayoutParams();
                int width = child == null ? 0 : child.getMeasuredWidth() + p.leftMargin + p.rightMargin;
                if (child == null || x > 0 && x + width > getWidth()) {
                    int rowX = 0;
                    for (int j = start; j < i; j++) {
                        View item = getChildAt(j); LayoutParams itemParams = (LayoutParams) item.getLayoutParams(); rowX += itemParams.leftMargin;
                        int itemTop = y + (line - item.getMeasuredHeight()) / 2;
                        item.layout(rowX, itemTop, rowX + item.getMeasuredWidth(), itemTop + item.getMeasuredHeight()); rowX += item.getMeasuredWidth() + itemParams.rightMargin;
                    }
                    start = i; x = 0; y += line; line = 0;
                }
                if (child != null) { x += width; line = Math.max(line, child.getMeasuredHeight()); }
            }
        }
    }

    private static final class LineText extends TextView {
        int lineHeight;
        LineText(Context context) { super(context); }
        @Override public void setText(CharSequence value, BufferType type) {
            if (lineHeight > 0 && value != null) {
                final int height = lineHeight;
                SpannableString string = new SpannableString(value.toString());
                string.setSpan((LineHeightSpan) (s, start, end, spanStart, v, fm) -> {
                    int extra = height - (fm.descent - fm.ascent);
                    fm.ascent -= extra / 2; fm.descent = fm.ascent + height; fm.top = fm.ascent; fm.bottom = fm.descent;
                }, 0, string.length(), Spanned.SPAN_INCLUSIVE_INCLUSIVE);
                super.setText(string, type);
            } else super.setText(value, type);
        }
    }

    static final class Sheet extends Dialog {
        private final View content;
        private final boolean drawer;
        private boolean closing;
        Sheet(Context context, View content, boolean drawer) {
            super(context); registerDialog(context, this); this.content = content; this.drawer = drawer;
            requestWindowFeature(Window.FEATURE_NO_TITLE);
            if (drawer) setContentView(content);
            else {
                ScrollView scroll = new ScrollView(context) {
                    @Override protected void onMeasure(int w, int h) {
                        int maximum = getResources().getDisplayMetrics().heightPixels - dp(getContext(), 88);
                        super.onMeasure(w, MeasureSpec.makeMeasureSpec(maximum, MeasureSpec.AT_MOST));
                    }
                };
                scroll.setFillViewport(false); scroll.setVerticalScrollBarEnabled(false); scroll.addView(content); setContentView(scroll);
            }
            Window window = getWindow();
            if (window != null) {
                GradientDrawable background = shape(context, SURFACE, drawer ? 0 : 6);
                if (drawer) { float r = dp(context, 20); background.setCornerRadii(new float[]{0, 0, r, r, r, r, 0, 0}); }
                window.setBackgroundDrawable(background); window.setWindowAnimations(0);
                int screen = context.getResources().getDisplayMetrics().widthPixels;
                WindowManager.LayoutParams p = window.getAttributes();
                p.width = drawer ? Math.min(dp(context, 280), Math.round(screen * .85f)) : Math.min(dp(context, 360), screen - dp(context, 40));
                p.height = drawer ? -1 : -2; p.gravity = drawer ? Gravity.START | Gravity.TOP : Gravity.CENTER;
                p.dimAmount = .6f; window.setAttributes(p); window.addFlags(WindowManager.LayoutParams.FLAG_DIM_BEHIND);
            }
        }
        @Override public void show() {
            closing = false; super.show();
            if (!ValueAnimator.areAnimatorsEnabled()) return;
            content.setAlpha(drawer ? 1 : 0); content.setTranslationX(drawer ? -dp(getContext(), 280) : 0);
            content.setTranslationY(drawer ? 0 : dp(getContext(), 4)); content.setScaleX(drawer ? 1 : .98f); content.setScaleY(drawer ? 1 : .98f);
            content.animate().alpha(1).translationX(0).translationY(0).scaleX(1).scaleY(1).setDuration(drawer ? 240 : 200).setInterpolator(MOTION).start();
        }
        @Override public void dismiss() {
            if (closing) return;
            if (!isShowing() || !ValueAnimator.areAnimatorsEnabled()) { super.dismiss(); return; }
            closing = true;
            content.animate().alpha(drawer ? 1 : 0).translationX(drawer ? -content.getWidth() : 0).scaleX(drawer ? 1 : .98f).scaleY(drawer ? 1 : .98f).setDuration(140).withEndAction(() -> { if (getWindow() != null) super.dismiss(); }).start();
        }
        void dismissImmediately() { content.animate().cancel(); super.dismiss(); }
    }

    static final class Icon extends View {
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        final Path path = new Path();
        final String kind;
        int color;
        float size = 24;
        Icon(Context c, String kind, int color) { super(c); this.kind = kind; this.color = color; setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO); }
        Icon size(float value) { size = value; return this; }
        void color(int value) { color = value; invalidate(); }
        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas); canvas.save();
            float scale = Math.min(dp(getContext(), size), Math.min(getWidth(), getHeight())) / 24f;
            canvas.translate(getWidth() / 2f - 12 * scale, getHeight() / 2f - 12 * scale); canvas.scale(scale, scale);
            paint.setColor(color); paint.setAlpha(255); paint.setStrokeWidth(2); paint.setStrokeCap(Paint.Cap.ROUND); paint.setStrokeJoin(Paint.Join.ROUND); paint.setStyle(Paint.Style.STROKE);
            Path p = path; p.reset();
            switch (kind) {
                case "menu": for (int y = 5; y <= 19; y += 7) canvas.drawLine(3, y, 21, y, paint); break;
                case "back": p.moveTo(12, 4); p.lineTo(4, 12); p.lineTo(12, 20); canvas.drawPath(p, paint); canvas.drawLine(4, 12, 20, 12, paint); break;
                case "close": canvas.drawLine(6, 6, 18, 18, paint); canvas.drawLine(18, 6, 6, 18, paint); break;
                case "next": p.moveTo(9, 6); p.lineTo(15, 12); p.lineTo(9, 18); canvas.drawPath(p, paint); break;
                case "down": paint.setStyle(Paint.Style.FILL); p.moveTo(7, 10); p.lineTo(17, 10); p.lineTo(12, 15); p.close(); canvas.drawPath(p, paint); break;
                case "check": paint.setStrokeWidth(1.8f); p.moveTo(4, 12); p.lineTo(9, 17); p.lineTo(21, 5); canvas.drawPath(p, paint); break;
                case "folder": paint.setStyle(Paint.Style.FILL); p.moveTo(2, 4); p.lineTo(10, 4); p.lineTo(12, 6); p.lineTo(22, 6); p.lineTo(22, 20); p.lineTo(2, 20); p.close(); canvas.drawPath(p, paint); break;
                case "key": paint.setStyle(Paint.Style.FILL); canvas.drawCircle(7, 12, 6, paint); canvas.drawRect(12, 10, 22, 14, paint); p.moveTo(18, 14); p.lineTo(20, 17); p.lineTo(23, 13); p.close(); canvas.drawPath(p, paint); paint.setColor(SURFACE); canvas.drawCircle(7, 12, 2.5f, paint); break;
                case "search": canvas.drawCircle(10.5f, 10.5f, 6.5f, paint); canvas.drawLine(16, 16, 21, 21, paint); break;
                case "more": paint.setStyle(Paint.Style.FILL); for (int y = 5; y <= 19; y += 7) canvas.drawCircle(12, y, 1.5f, paint); break;
                case "sort": canvas.drawLine(3, 6, 21, 6, paint); canvas.drawLine(3, 12, 15, 12, paint); canvas.drawLine(3, 18, 9, 18, paint); break;
                case "home": paint.setStyle(Paint.Style.FILL); p.moveTo(2, 10); p.lineTo(12, 2); p.lineTo(22, 10); p.lineTo(19, 10); p.lineTo(19, 21); p.lineTo(14, 21); p.lineTo(14, 14); p.lineTo(10, 14); p.lineTo(10, 21); p.lineTo(5, 21); p.lineTo(5, 10); p.close(); canvas.drawPath(p, paint); break;
                case "save": p.moveTo(5, 3); p.lineTo(17, 3); p.lineTo(21, 7); p.lineTo(21, 21); p.lineTo(3, 21); p.lineTo(3, 3); p.close(); canvas.drawPath(p, paint); canvas.drawRect(7, 3, 17, 9, paint); canvas.drawRect(7, 13, 17, 21, paint); break;
                case "tools": canvas.drawRect(4, 4, 10, 10, paint); canvas.drawRect(14, 4, 20, 10, paint); canvas.drawRect(4, 14, 10, 20, paint); canvas.drawRect(14, 14, 20, 20, paint); break;
                case "android":
                    paint.setStyle(Paint.Style.FILL); canvas.drawArc(1, 5, 23, 25, 180, 180, true, paint);
                    paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(1.4f); canvas.drawLine(7, 7, 4, 2, paint); canvas.drawLine(17, 7, 20, 2, paint);
                    paint.setStyle(Paint.Style.FILL); paint.setColor(Color.WHITE); canvas.drawCircle(7, 12, 1, paint); canvas.drawCircle(17, 12, 1, paint); break;
                case "sun": paint.setStyle(Paint.Style.STROKE); canvas.drawCircle(12,12,4,paint); for(int i=0;i<8;i++){ double a=i*Math.PI/4; float x1=12+(float)Math.cos(a)*7, y1=12+(float)Math.sin(a)*7, x2=12+(float)Math.cos(a)*9.5f, y2=12+(float)Math.sin(a)*9.5f; canvas.drawLine(x1,y1,x2,y2,paint);} break;
                case "moon": paint.setStyle(Paint.Style.FILL); p.moveTo(15,3); p.cubicTo(10,3,6,7,6,12); p.cubicTo(6,17,10,21,15,21); p.cubicTo(12.5f,21,10.2f,20,8.5f,18.3f); p.cubicTo(11.5f,19,14,18,16,16); p.cubicTo(18,14,18.5f,11,17.5f,8.5f); p.cubicTo(16.8f,6.5f,16,4.5f,15,3); p.close(); canvas.drawPath(p, paint); break;
                default: canvas.drawCircle(12, 12, 8, paint);
            }
            canvas.restore();
        }
    }

    static final class Choice extends View {
        final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        final Path path = new Path();
        private final boolean square;
        float amount;
        boolean mixed, selected;
        ValueAnimator animator;
        Choice(Context c) { this(c, false); }
        Choice(Context c, boolean square) { super(c); this.square = square; setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO); }
        void checked(boolean value, boolean animate) {
            selected = value; float target = value || mixed ? 1 : 0;
            if (amount == target) { invalidate(); return; }
            if (animator != null) animator.cancel();
            if (!animate || !ValueAnimator.areAnimatorsEnabled()) { amount = target; invalidate(); return; }
            animator = ValueAnimator.ofFloat(amount, target); animator.setDuration(180); animator.setInterpolator(MOTION);
            animator.addUpdateListener(a -> { amount = (float) a.getAnimatedValue(); invalidate(); }); animator.start();
        }
        @Override public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
            super.onInitializeAccessibilityNodeInfo(info); info.setClassName("android.widget.CheckBox"); info.setCheckable(true); info.setChecked(selected);
        }
        @Override protected void onDraw(Canvas c) {
            float cx = getWidth() / 2f, cy = getHeight() / 2f, stroke = dp(getContext(), 2), r = Math.min(getWidth(), getHeight()) / 2f - stroke / 2;
            paint.setAlpha(255); paint.setColor(square && amount == 0 ? 0xff49454f : PURPLE); paint.setStyle(Paint.Style.STROKE); paint.setStrokeWidth(stroke);
            if (square) c.drawRoundRect(cx-r, cy-r, cx+r, cy+r, dp(getContext(), 1), dp(getContext(), 1), paint); else c.drawCircle(cx, cy, r, paint);
            if (amount > 0) {
                paint.setStyle(Paint.Style.FILL); paint.setColor(PURPLE); paint.setAlpha(Math.round(255 * amount));
                if (square) c.drawRoundRect(cx-r, cy-r, cx+r, cy+r, dp(getContext(), 1), dp(getContext(), 1), paint); else c.drawCircle(cx, cy, r, paint);
                paint.setColor(Color.WHITE); paint.setAlpha(Math.round(255 * amount)); paint.setStyle(Paint.Style.STROKE); paint.setStrokeCap(Paint.Cap.ROUND); paint.setStrokeJoin(Paint.Join.ROUND);
                c.save(); float scale = .6f + .4f * amount; c.scale(scale, scale, cx, cy);
                Path p = path; p.reset();
                if (mixed) { p.moveTo(cx-r*.5f, cy); p.lineTo(cx+r*.5f, cy); }
                else { p.moveTo(cx-r*.52f, cy); p.lineTo(cx-r*.12f, cy+r*.35f); p.lineTo(cx+r*.6f, cy-r*.43f); }
                c.drawPath(p, paint); c.restore(); paint.setAlpha(255);
            }
        }
    }
}
