package cn.beingyi.fallen.shield1;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Intent;
import android.content.pm.ApplicationInfo;

@TargetApi(28)
public final class SubAppComponentFactory extends AppComponentFactory {
    private volatile AppComponentFactory original;
    private volatile boolean initialized;

    private synchronized AppComponentFactory factory(ClassLoader loader) {
        if (initialized) return original;
        SubApp.prepareFromRuntime(loader);
        String name = SubApp.originalFactory();
        if (!name.isEmpty() && !name.equals(AppComponentFactory.class.getName()) && !name.equals(getClass().getName())) {
            try {
                original = Class.forName(name, true, loader).asSubclass(AppComponentFactory.class).getDeclaredConstructor().newInstance();
            } catch (ReflectiveOperationException error) {
                throw new IllegalStateException("Cannot create original AppComponentFactory: " + name, error);
            }
        }
        initialized = true;
        return original;
    }

    @TargetApi(29)
    @Override public ClassLoader instantiateClassLoader(ClassLoader loader, ApplicationInfo info) {
        SubApp.prepare(loader, info.sourceDir, info.dataDir);
        AppComponentFactory delegate = factory(loader);
        return delegate == null ? super.instantiateClassLoader(loader, info) : delegate.instantiateClassLoader(loader, info);
    }

    @Override public Application instantiateApplication(ClassLoader loader, String name) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = factory(loader);
        String originalName = SubApp.originalApplication();
        return delegate == null ? super.instantiateApplication(loader, originalName) : delegate.instantiateApplication(loader, originalName);
    }

    @Override public Activity instantiateActivity(ClassLoader loader, String name, Intent intent) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = factory(loader);
        return delegate == null ? super.instantiateActivity(loader, name, intent) : delegate.instantiateActivity(loader, name, intent);
    }

    @Override public Service instantiateService(ClassLoader loader, String name, Intent intent) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = factory(loader);
        return delegate == null ? super.instantiateService(loader, name, intent) : delegate.instantiateService(loader, name, intent);
    }

    @Override public BroadcastReceiver instantiateReceiver(ClassLoader loader, String name, Intent intent) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = factory(loader);
        return delegate == null ? super.instantiateReceiver(loader, name, intent) : delegate.instantiateReceiver(loader, name, intent);
    }

    @Override public ContentProvider instantiateProvider(ClassLoader loader, String name) throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AppComponentFactory delegate = factory(loader);
        return delegate == null ? super.instantiateProvider(loader, name) : delegate.instantiateProvider(loader, name);
    }
}
