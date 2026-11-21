package io.dexpack.tool;

import android.app.Dialog;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.net.Uri;
import android.os.Looper;
import android.view.View;
import android.widget.TextView;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.GraphicsMode;
import org.robolectric.shadows.ShadowDialog;
import java.io.File;
import java.io.FileOutputStream;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.Assert.*;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 28, qualifiers = "w360dp-h694dp-mdpi")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
public class UiFlowTest {
    private static final String[] CLASSES = {"Lcom/example/Main;", "Lcom/example/Worker;", "Lorg/example/Parser;"};
    @Test public void emptyHomeRendersAndCannotStart() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); ProtectionApp app = (ProtectionApp) a.getApplication();
            assertFalse(app.ready()); assertFalse(tag(a, "startProcessing").isEnabled());
            capture(a.findViewById(android.R.id.content), "home-empty", 360, 694);
            assertEquals(74, tag(a, "selectionCard").getHeight()); assertEquals(80, tag(a, "feature0").getHeight()); assertEquals(64, tag(a, "feature1").getHeight());
            tag(a, "selectApk").performClick(); settle(); Dialog picker = ShadowDialog.getLatestDialog();
            assertTrue(picker.isShowing()); captureDialog(a, picker, "choose-apk");
        }
    }
    @Test public void shieldSelectionAndSigningDialogRetainReferenceLayout() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); ProtectionApp app = (ProtectionApp) a.getApplication(); fixture(app); tag(a, "feature0").performClick(); settle();
            assertTrue(app.ready()); capture(a.findViewById(android.R.id.content), "home-shield", 360, 694);
            tag(a, "startProcessing").performClick(); settle(); Dialog signing = ShadowDialog.getLatestDialog(); assertTrue(signing.isShowing());
            for (int i = 1; i <= 3; i++) assertNotNull(signing.getWindow().getDecorView().findViewWithTag("scheme" + i));
            captureDialog(a, signing, "signing");
        }
    }
    @Test public void signatureKillerNeedsNoClassSelection() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); ProtectionApp app = (ProtectionApp) a.getApplication(); fixture(app);
            tag(a, "feature3").performClick(); settle();
            assertTrue(app.ready()); assertEquals(3, app.mode);
            assertEquals(View.GONE, tag(a, "classArea").getVisibility());
            capture(a.findViewById(android.R.id.content), "home-signature-killer", 360, 694);
        }
    }
    @Test public void v1AndV2KeepSeparateSelectionsAndSaveOrCancelCorrectly() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); ProtectionApp app = (ProtectionApp) a.getApplication(); fixture(app);
            tag(a, "feature1").performClick(); settle(); assertFalse(app.ready()); tag(a, "selectClasses").performClick(); settle();
            Dialog picker = ShadowDialog.getLatestDialog(); assertTrue(picker instanceof ClassPicker);
            picker.getWindow().getDecorView().findViewWithTag("classesAll").performClick(); settle();
            capture(picker.findViewById(android.R.id.content), "classes-v1", 360, 694);
            picker.getWindow().getDecorView().findViewWithTag("classesSave").performClick(); settle();
            assertEquals(3, app.v1Classes.size()); assertTrue(app.ready()); capture(a.findViewById(android.R.id.content), "home-v1", 360, 694);
            tag(a, "feature2").performClick(); settle(); assertFalse(app.ready()); assertTrue(app.v2Classes.isEmpty()); tag(a, "selectClasses").performClick(); settle();
            Dialog second = ShadowDialog.getLatestDialog(); second.getWindow().getDecorView().findViewWithTag("classesAll").performClick(); second.getWindow().getDecorView().findViewWithTag("classesBack").performClick(); settle(); assertTrue(app.v2Classes.isEmpty());
            tag(a, "selectClasses").performClick(); settle(); Dialog third = ShadowDialog.getLatestDialog(); third.getWindow().getDecorView().findViewWithTag("classesAll").performClick(); third.getWindow().getDecorView().findViewWithTag("classesDone").performClick(); settle(); assertEquals(3, app.v2Classes.size());
            capture(a.findViewById(android.R.id.content), "home-v2", 360, 694);
            tag(a, "clearClasses").performClick(); assertFalse(app.ready()); assertEquals(3, app.v1Classes.size());
        }
    }
    @Test public void signingModesValidateBeforeConfirming() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); ProtectionApp app = (ProtectionApp) a.getApplication(); AtomicBoolean confirmed = new AtomicBoolean();
            new SigningDialog(a, app, false, () -> fail("Unexpected import"), () -> confirmed.set(true)).show(); settle(); Dialog d = ShadowDialog.getLatestDialog();
            for (int i = 1; i <= 3; i++) d.getWindow().getDecorView().findViewWithTag("scheme" + i).performClick();
            d.getWindow().getDecorView().findViewWithTag("confirmSigning").performClick(); assertFalse(confirmed.get()); assertTrue(d.isShowing());
            d.getWindow().getDecorView().findViewWithTag("scheme2").performClick(); d.getWindow().getDecorView().findViewWithTag("confirmSigning").performClick(); settle();
            assertTrue(confirmed.get()); assertArrayEquals(new boolean[]{false, true, false}, app.schemes);
        }
    }
    @Test public void progressAndOutputUseTheExecutorDialog() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); ProtectionApp app = (ProtectionApp) a.getApplication(); fixture(app); app.mode = 0; app.hasExecution = true; app.processing = true; app.busy = true; app.percent = 30; app.status = "Building DEX…"; app.notifyState();
            ExecutorDialog executor = new ExecutorDialog(a, app); executor.show(); executor.update(); settle(); Dialog d = ShadowDialog.getLatestDialog(); captureDialog(a, d, "executor-running");
            app.percent = 100; app.processing = false; app.busy = false; app.saved = new Storage.Saved(Uri.parse("file:///storage/emulated/0/Download/Telegram/sample-protected.apk"), "/storage/emulated/0/Download/Telegram/sample-protected.apk", true); app.status = "Output saved"; app.notifyState(); executor.update(); settle();
            assertEquals(View.VISIBLE, tag(a, "viewOutput").getVisibility()); captureDialog(a, d, "executor-complete"); executor.dismissImmediately();
            tag(a, "viewOutput").performClick(); settle(); assertTrue(ShadowDialog.getLatestDialog().isShowing());
        }
    }
    @Test public void drawerAndSigningSettingsUseNativeScreens() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); tag(a, "menu").performClick(); settle(); Dialog drawer = ShadowDialog.getLatestDialog(); captureDialog(a, drawer, "drawer"); ((Ui.Sheet) drawer).dismissImmediately();
            new SigningSettings(a, (ProtectionApp) a.getApplication(), () -> { }, key -> { }).show(); settle(); Dialog settings = ShadowDialog.getLatestDialog();
            assertFalse(settings.getWindow().getDecorView().findViewWithTag("loadKey").isEnabled()); capture(settings.findViewById(android.R.id.content), "signing-settings", 360, 694);
        }
    }
    @Test public void drawerOpensTestSignatureScreen() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); tag(a, "menu").performClick(); settle();
            Dialog drawer = ShadowDialog.getLatestDialog();
            drawer.getWindow().getDecorView().findViewWithTag("drawerSignatureTest").performClick(); settle();
            Dialog test = ShadowDialog.getLatestDialog();
            assertNotNull(test.getWindow().getDecorView().findViewWithTag("inspectSelected"));
            assertNotNull(test.getWindow().getDecorView().findViewWithTag("inspectOtherApk"));
            assertNotNull(test.getWindow().getDecorView().findViewWithTag("signatureReport"));
            capture(test.findViewById(android.R.id.content), "test-signature", 360, 694);
        }
    }
    @Test public void drawerOpensRuntimeHookScreen() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); tag(a, "menu").performClick(); settle();
            Dialog drawer = ShadowDialog.getLatestDialog();
            drawer.getWindow().getDecorView().findViewWithTag("drawerRuntimeHook").performClick(); settle();
            Dialog hook = ShadowDialog.getLatestDialog();
            assertNotNull(hook.getWindow().getDecorView().findViewWithTag("runtimeHookTargetField"));
            assertNotNull(hook.getWindow().getDecorView().findViewWithTag("runtimeHookAddTarget"));
            assertNotNull(hook.getWindow().getDecorView().findViewWithTag("runtimeHookTargetList"));
            assertNotNull(hook.getWindow().getDecorView().findViewWithTag("runtimeHookChooseCert"));
            assertNotNull(hook.getWindow().getDecorView().findViewWithTag("runtimeHookSave"));
            captureDialog(a, hook, "runtime-hook");
        }
    }
    @Test public void classSearchAndPartialPackageSelectionAreUsable() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); Set<String> selection = new HashSet<>(); selection.add(CLASSES[0]);
            ClassPicker picker = new ClassPicker(a, CLASSES, selection, "Select classes for String Encryption V2", () -> { }); picker.show(); settle();
            ((TextView) picker.getWindow().getDecorView().findViewWithTag("classSearch")).setText("Worker"); settle();
            capture(picker.findViewById(android.R.id.content), "classes-search", 360, 694);
            android.widget.ListView tree = (android.widget.ListView) picker.getWindow().getDecorView().findViewWithTag("classTree"); assertEquals(1, tree.getCount());
            View row = tree.getAdapter().getView(0, null, tree); ((android.view.ViewGroup) row).getChildAt(1).performClick();
            picker.getWindow().getDecorView().findViewWithTag("classesSave").performClick(); assertEquals(2, selection.size()); assertTrue(selection.contains(CLASSES[1]));
        }
    }
    @Test @Config(qualifiers = "w320dp-h640dp-mdpi") public void smallScreenRetainsControls() throws Exception {
        try (var controller = Robolectric.buildActivity(MainActivity.class).setup()) {
            MainActivity a = controller.get(); fixture((ProtectionApp) a.getApplication()); tag(a, "feature2").performClick(); settle(); capture(a.findViewById(android.R.id.content), "home-small", 320, 640);
            assertTrue(tag(a, "feature2").getHeight() >= 64); assertEquals(View.VISIBLE, tag(a, "classArea").getVisibility());
        }
    }
    private static View tag(MainActivity a, String name) { View v = a.getWindow().getDecorView().findViewWithTag(name); assertNotNull(name, v); return v; }
    private static void fixture(ProtectionApp app) {
        File file = new File(app.getCacheDir(), "ui-fixture.apk");
        app.input = new Storage.Input(file, file, "base (1).apk", "CyberAlpha Encryptor v1.2", "/storage/emulated/0/Download/Telegram/base (1).apk", new String[]{"com.cyberalpha.stringtobyte", "", "21", "28"}, null); app.allClasses = CLASSES; app.notifyState();
    }
    private static void settle() { shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300)); }
    private static void layout(View view, int width, int height) { view.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY), View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY)); view.layout(0, 0, width, height); }
    static void capture(View view, String name, int width, int height) throws Exception {
        layout(view, width, height); Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888); view.draw(new Canvas(bitmap)); save(bitmap, name);
    }
    private static void captureDialog(MainActivity a, Dialog dialog, String name) throws Exception {
        View home = a.findViewById(android.R.id.content); layout(home, 360, 694); Bitmap bitmap = Bitmap.createBitmap(360, 694, Bitmap.Config.ARGB_8888); Canvas canvas = new Canvas(bitmap); home.draw(canvas);
        Paint dim = new Paint(); dim.setColor(0x99000000); canvas.drawRect(0, 0, 360, 694, dim);
        View view = dialog.getWindow().getDecorView(); boolean drawer = name.equals("drawer"); int width = drawer ? 280 : 320;
        view.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY), View.MeasureSpec.makeMeasureSpec(drawer ? 694 : 654, drawer ? View.MeasureSpec.EXACTLY : View.MeasureSpec.AT_MOST));
        view.layout(0, 0, width, view.getMeasuredHeight()); canvas.translate(drawer ? 0 : 20, drawer ? 0 : (694 - view.getHeight()) / 2f); view.draw(canvas); save(bitmap, name);
    }
    private static void save(Bitmap bitmap, String name) throws Exception {
        File dir = new File("build/ui-snapshots"); assertTrue(dir.isDirectory() || dir.mkdirs());
        try (FileOutputStream out = new FileOutputStream(new File(dir, name + ".png"))) { bitmap.compress(Bitmap.CompressFormat.PNG, 100, out); } bitmap.recycle();
    }
}
