import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('apk', type=Path)
    parser.add_argument('work', type=Path)
    parser.add_argument('--java-home', type=Path, default=os.environ.get('JAVA_HOME'))
    args = parser.parse_args()
    if args.java_home is None:
        parser.error('JAVA_HOME or --java-home is required')
    project = Path(__file__).resolve().parent.parent
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    cpp = project / 'app/src/main/cpp'
    runtime = project / 'shield/src/main/cpp'
    library = work / 'libScKitShieldV1.so'
    subprocess.run([
        os.environ.get('CXX', 'c++'), '-std=c++17', '-O2', '-fPIC', '-shared', '-Wall', '-Wextra',
        '-I' + str(cpp), '-I' + str(args.java_home / 'include'), '-I' + str(args.java_home / 'include/linux'),
        str(runtime / 'loader.cpp'), str(runtime / 'payload.cpp'), str(cpp / 'archive.cpp'), str(cpp / 'bytes.cpp'),
        '-lz', '-o', str(library)
    ], check=True)
    sources = {
        'android/os/Build.java': '''package android.os;
public final class Build { public static final class VERSION { public static int SDK_INT = 27; } }''',
        'android/content/pm/ApplicationInfo.java': '''package android.content.pm;
public class ApplicationInfo { public String sourceDir, dataDir, className; }''',
        'android/content/Context.java': '''package android.content;
public class Context {
 public static android.content.pm.ApplicationInfo info;
 public static ClassLoader loader;
 public android.content.pm.ApplicationInfo getApplicationInfo() { return info; }
 public ClassLoader getClassLoader() { return loader; }
}''',
        'android/app/Application.java': '''package android.app;
public class Application extends android.content.Context {
 public int creates;
 protected void attachBaseContext(android.content.Context base) {}
 public void onCreate() { creates++; }
}''',
        'android/app/Instrumentation.java': 'package android.app; public class Instrumentation {}',
        'android/util/ArrayMap.java': 'package android.util; public class ArrayMap<K,V> extends java.util.LinkedHashMap<K,V> {}',
        'android/content/ContentProvider.java': 'package android.content; public class ContentProvider { public Context mContext; }',
        'android/app/LoadedApk.java': '''package android.app;
public class LoadedApk {
 public Application mApplication;
 public android.content.pm.ApplicationInfo mApplicationInfo;
 public int calls;
 public Application makeApplication(boolean forceDefault, Instrumentation instrumentation) {
  if (forceDefault || instrumentation != null || mApplication != null) throw new AssertionError("Wrong Application handoff");
  calls++; mApplication = new Application();
  ActivityThread.currentActivityThread().mAllApplications.add(mApplication);
  return mApplication;
 }
}''',
        'android/app/ActivityThread.java': '''package android.app;
public class ActivityThread {
 public static final ActivityThread thread = new ActivityThread();
 public static ActivityThread currentActivityThread() { return thread; }
 public AppBindData mBoundApplication = new AppBindData();
 public Application mInitialApplication;
 public java.util.ArrayList<Application> mAllApplications = new java.util.ArrayList<>();
 public android.util.ArrayMap<String,ProviderClientRecord> mProviderMap = new android.util.ArrayMap<>();
 public static class AppBindData {
  public LoadedApk info = new LoadedApk();
  public android.content.pm.ApplicationInfo appInfo;
 }
 public static class ProviderClientRecord { public android.content.ContentProvider mLocalProvider; }
}''',
        'dalvik/system/DexPathList.java': '''package dalvik.system;
public class DexPathList {
 public Element[] dexElements;
 public DexPathList(String[] paths) { dexElements = java.util.Arrays.stream(paths).map(Element::new).toArray(Element[]::new); }
 public static class Element { public final String path; public Element(String value) { path = value; } }
}''',
        'dalvik/system/BaseDexClassLoader.java': '''package dalvik.system;
public class BaseDexClassLoader extends ClassLoader {
 public final DexPathList pathList;
 public BaseDexClassLoader(String[] paths, ClassLoader parent) { super(parent); pathList = new DexPathList(paths); }
}''',
        'dalvik/system/DexClassLoader.java': '''package dalvik.system;
public class DexClassLoader extends BaseDexClassLoader {
 public static int constructions;
 public DexClassLoader(String paths, String optimized, String libraries, ClassLoader parent) {
  super(paths.split(":"), parent); constructions++;
  if (!new java.io.File(optimized).isDirectory() || libraries != null) throw new AssertionError("Wrong loader paths");
  for (DexPathList.Element element : pathList.dexElements) {
   java.nio.file.Path path = java.nio.file.Paths.get(element.path);
   try {
    if (!java.nio.file.Files.isRegularFile(path) || java.nio.file.Files.size(path) < 112) throw new AssertionError("Missing DEX");
    if (java.nio.file.Files.getPosixFilePermissions(path).contains(java.nio.file.attribute.PosixFilePermission.OWNER_WRITE)) throw new AssertionError("Writable DEX");
   } catch (java.io.IOException failure) { throw new AssertionError(failure); }
  }
 }
}''',
        'cn/beingyi/sckit/shield1/LoaderTest.java': '''package cn.beingyi.sckit.shield1;
import android.app.*;
import android.content.*;
import android.content.pm.ApplicationInfo;
import dalvik.system.*;
public class LoaderTest {
 static void check(boolean value, String name) { if (!value) throw new AssertionError(name); }
 static BaseDexClassLoader loader() { return new BaseDexClassLoader(new String[]{"shell.dex"}, LoaderTest.class.getClassLoader()); }
 public static void main(String[] args) {
  ApplicationInfo info = new ApplicationInfo(); info.sourceDir = args[0]; info.dataDir = args[1];
  Context.info = info; BaseDexClassLoader base = loader(); Context.loader = base;
  ActivityThread thread = ActivityThread.currentActivityThread(); thread.mBoundApplication.appInfo = info;
  thread.mBoundApplication.info.mApplicationInfo = info;
  SubApp.prepare(base, info.sourceDir, info.dataDir);
  int size = base.pathList.dexElements.length; check(size > 1, "Packed DEX elements missing");
  check(base.pathList.dexElements[0].path.equals("shell.dex"), "Original element lost");
  SubApp.prepare(base, info.sourceDir, info.dataDir); SubApp.prepareFromRuntime(base); SubApp.attach(new Context());
  check(DexClassLoader.constructions == 1 && size == base.pathList.dexElements.length, "Preparation is not idempotent");
  BaseDexClassLoader second = loader(); SubApp.prepareFromRuntime(second);
  check(second.pathList.dexElements.length == size, "Android 9 preparation failed");
  BaseDexClassLoader retry = loader(); boolean failed = false;
  try { SubApp.prepare(retry, info.sourceDir + ".missing", info.dataDir); }
  catch (IllegalStateException expected) { failed = true; }
  check(failed && retry.pathList.dexElements.length == 1, "Failed preparation mutated loader");
  SubApp.prepare(retry, info.sourceDir, info.dataDir); check(retry.pathList.dexElements.length == size, "Preparation retry failed");
  SubApp shell = new SubApp(); thread.mInitialApplication = shell; thread.mAllApplications.add(shell);
  thread.mBoundApplication.info.mApplication = shell;
  ActivityThread.ProviderClientRecord local = new ActivityThread.ProviderClientRecord();
  local.mLocalProvider = new ContentProvider(); local.mLocalProvider.mContext = shell;
  thread.mProviderMap.put("local", local); thread.mProviderMap.put("remote", new ActivityThread.ProviderClientRecord());
  SubApp.create(shell); Application original = thread.mInitialApplication;
  check(original != shell && original == thread.mBoundApplication.info.mApplication, "Application was not replaced");
  check(info.className != null && !info.className.equals(SubApp.class.getName()), "Original Application name missing");
  check(thread.mAllApplications.size() == 1 && thread.mAllApplications.get(0) == original, "Application list was not restored");
  check(local.mLocalProvider.mContext == original, "Provider context was not restored");
  check(original.creates == 1 && thread.mBoundApplication.info.calls == 1, "Original Application startup failed");
  SubApp.create(shell); check(original.creates == 1 && thread.mBoundApplication.info.calls == 1, "Application started twice");
  System.out.println("PASS: JNI DEX merge, idempotence, Android 9 preparation, error retry, Application and provider handoff");
 }
}'''
    }
    files = []
    for name, body in sources.items():
        file = work / 'src' / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(body, encoding='utf-8')
        files.append(str(file))
    files.append(str(project / 'shield/src/main/java/cn/beingyi/sckit/shield1/SubApp.java'))
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac'), '-d', str(classes), *files], check=True)
    data = work / 'data'
    data.mkdir()
    subprocess.run([str(args.java_home / 'bin/java'), '-Xcheck:jni', '-Djava.library.path=' + str(work), '-cp', str(classes),
                    'cn.beingyi.sckit.shield1.LoaderTest', str(args.apk.resolve()), str(data)], check=True)


if __name__ == '__main__':
    main()
