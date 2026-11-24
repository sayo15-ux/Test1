package cn.beingyi.fallen.shield1;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.IBinder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 28, manifest = Config.NONE, shadows = ComponentFactoryTest.Runtime.class)
public class ComponentFactoryTest {
    @Implements(value = SubApp.class, isInAndroidSdk = false)
    public static class Runtime {
        static String application, factory;
        static int prepares, explicitPrepares;
        static boolean fail;
        @Implementation protected static void __staticInitializer__() {}
        @Implementation protected static void prepareFromRuntime(ClassLoader loader) {
            prepares++;
            if (fail) throw new IllegalStateException("Broken payload");
        }
        @Implementation protected static void prepare(ClassLoader loader, String apk, String data) { explicitPrepares++; }
        @Implementation protected static String originalApplication() { return application; }
        @Implementation protected static String originalFactory() { return factory; }
    }
    public static class OriginalApplication extends Application {}
    public static class OriginalActivity extends Activity {}
    public static class OriginalService extends Service { @Override public IBinder onBind(Intent intent) { return null; } }
    public static class OriginalReceiver extends BroadcastReceiver { @Override public void onReceive(Context context, Intent intent) {} }
    public static class OriginalProvider extends ContentProvider {
        @Override public boolean onCreate() { return true; }
        @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) { return null; }
        @Override public String getType(Uri uri) { return null; }
        @Override public Uri insert(Uri uri, ContentValues values) { return null; }
        @Override public int delete(Uri uri, String selection, String[] args) { return 0; }
        @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { return 0; }
    }
    public static class Delegate extends AppComponentFactory {
        static int applications, activities, services, receivers, providers, loaders;
        public Delegate() { assertTrue(Runtime.prepares > 0); }
        @Override public Application instantiateApplication(ClassLoader cl, String name) { applications++; assertEquals(OriginalApplication.class.getName(), name); return new OriginalApplication(); }
        @Override public Activity instantiateActivity(ClassLoader cl, String name, Intent intent) { activities++; return new OriginalActivity(); }
        @Override public Service instantiateService(ClassLoader cl, String name, Intent intent) { services++; return new OriginalService(); }
        @Override public BroadcastReceiver instantiateReceiver(ClassLoader cl, String name, Intent intent) { receivers++; return new OriginalReceiver(); }
        @Override public ContentProvider instantiateProvider(ClassLoader cl, String name) { providers++; return new OriginalProvider(); }
        @Override public ClassLoader instantiateClassLoader(ClassLoader cl, ApplicationInfo info) { loaders++; return cl; }
    }
    private ClassLoader loader;
    @Before public void before() {
        loader = getClass().getClassLoader();
        Runtime.application = OriginalApplication.class.getName(); Runtime.factory = "";
        Runtime.prepares = Runtime.explicitPrepares = 0; Runtime.fail = false;
        Delegate.applications = Delegate.activities = Delegate.services = Delegate.receivers = Delegate.providers = Delegate.loaders = 0;
    }
    @Test public void androidNinePreparesBeforeOriginalApplication() throws Exception {
        Application app = new SubAppComponentFactory().instantiateApplication(loader, SubApp.class.getName());
        assertTrue(app instanceof OriginalApplication); assertEquals(1, Runtime.prepares);
    }
    @Test public void delegatesAllComponentsAndInitializesOnce() throws Exception {
        Runtime.factory = Delegate.class.getName(); SubAppComponentFactory factory = new SubAppComponentFactory();
        assertTrue(factory.instantiateApplication(loader, SubApp.class.getName()) instanceof OriginalApplication);
        assertTrue(factory.instantiateActivity(loader, OriginalActivity.class.getName(), new Intent()) instanceof OriginalActivity);
        assertTrue(factory.instantiateService(loader, OriginalService.class.getName(), new Intent()) instanceof OriginalService);
        assertTrue(factory.instantiateReceiver(loader, OriginalReceiver.class.getName(), new Intent()) instanceof OriginalReceiver);
        assertTrue(factory.instantiateProvider(loader, OriginalProvider.class.getName()) instanceof OriginalProvider);
        assertEquals(1, Delegate.applications); assertEquals(1, Delegate.activities); assertEquals(1, Delegate.services);
        assertEquals(1, Delegate.receivers); assertEquals(1, Delegate.providers); assertEquals(1, Runtime.prepares);
    }
    @Test public void keepsDefaultComponentConstruction() throws Exception {
        SubAppComponentFactory factory = new SubAppComponentFactory();
        assertTrue(factory.instantiateActivity(loader, OriginalActivity.class.getName(), null) instanceof OriginalActivity);
        assertTrue(factory.instantiateProvider(loader, OriginalProvider.class.getName()) instanceof OriginalProvider);
        assertEquals(1, Runtime.prepares);
    }
    @Test public void reportsMissingOriginalFactory() {
        Runtime.factory = "missing.Factory";
        assertThrows(IllegalStateException.class, () -> new SubAppComponentFactory().instantiateApplication(loader, "ignored"));
    }
    @Test public void doesNotInstantiateAfterPayloadFailure() {
        Runtime.fail = true; Runtime.factory = Delegate.class.getName();
        assertThrows(IllegalStateException.class, () -> new SubAppComponentFactory().instantiateApplication(loader, "ignored"));
        assertEquals(0, Delegate.applications);
    }
    @Test @Config(sdk = 29) public void androidTenPreparesAndDelegatesClassLoader() {
        Runtime.factory = Delegate.class.getName(); ApplicationInfo info = new ApplicationInfo();
        info.sourceDir = "/base.apk"; info.dataDir = "/data";
        assertSame(loader, new SubAppComponentFactory().instantiateClassLoader(loader, info));
        assertEquals(1, Runtime.explicitPrepares); assertEquals(1, Delegate.loaders);
    }
}
