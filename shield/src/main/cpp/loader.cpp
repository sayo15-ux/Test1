#include "payload.hpp"
#include <jni.h>
#include <mutex>

namespace {
    struct JavaException {};
    void check(JNIEnv* env) { if (env->ExceptionCheck()) throw JavaException{}; }
    jclass type(JNIEnv* env, const char* name) {
        jclass result = env->FindClass(name); check(env); return result;
    }
    jmethodID method(JNIEnv* env, jclass cls, const char* name, const char* sig) {
        jmethodID result = env->GetMethodID(cls, name, sig); check(env); return result;
    }
    jfieldID field(JNIEnv* env, jclass cls, const char* name, const char* sig) {
        jfieldID result = env->GetFieldID(cls, name, sig); check(env); return result;
    }
    jobject get(JNIEnv* env, jobject object, const char* name, const char* sig) {
        auto cls = env->GetObjectClass(object); check(env);
        auto id = field(env, cls, name, sig); env->DeleteLocalRef(cls);
        auto result = env->GetObjectField(object, id); check(env); return result;
    }
    void set(JNIEnv* env, jobject object, const char* name, const char* sig, jobject value) {
        auto cls = env->GetObjectClass(object); check(env);
        auto id = field(env, cls, name, sig); env->DeleteLocalRef(cls);
        env->SetObjectField(object, id, value); check(env);
    }
    std::string text(JNIEnv* env, jstring value) {
        dexpack::require(value != nullptr, "Missing Shield path.");
        const jchar* chars = env->GetStringChars(value, nullptr); check(env);
        dexpack::Text out(reinterpret_cast<const char16_t*>(chars), env->GetStringLength(value));
        env->ReleaseStringChars(value, chars); return dexpack::utf8(out);
    }
    jstring text(JNIEnv* env, const std::string& value) {
        auto chars = dexpack::utf16(value);
        auto result = env->NewString(reinterpret_cast<const jchar*>(chars.data()), jsize(chars.size())); check(env); return result;
    }
    jobject activityThread(JNIEnv* env) {
        auto cls = type(env, "android/app/ActivityThread");
        auto id = env->GetStaticMethodID(cls, "currentActivityThread", "()Landroid/app/ActivityThread;"); check(env);
        auto thread = env->CallStaticObjectMethod(cls, id); check(env);
        dexpack::require(thread != nullptr, "Android application thread is unavailable."); return thread;
    }
    jobject boundApplication(JNIEnv* env, jobject thread) {
        auto bound = get(env, thread, "mBoundApplication", "Landroid/app/ActivityThread$AppBindData;");
        dexpack::require(bound != nullptr, "Android application data is unavailable."); return bound;
    }
    std::recursive_mutex mutex;
    struct Prepared {
        jobject loader;
        std::string application;
    };
    std::vector<Prepared> prepared;
    jobject originalApplication = nullptr;
    bool creatingApplication = false;

    const Prepared& prepare(JNIEnv* env, jobject loader, const std::string& apk, const std::string& data) {
        dexpack::require(loader != nullptr, "Application class loader is unavailable.");
        for (const auto& entry : prepared) if (env->IsSameObject(loader, entry.loader)) return entry;
        auto installed = dexpack::shield::install(apk, data);
        std::string paths;
        for (const auto& path : installed.dexPaths) { if (!paths.empty()) paths += ':'; paths += path; }

        auto cls = type(env, "dalvik/system/DexClassLoader");
        auto constructor = method(env, cls, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        auto extra = env->NewObject(cls, constructor, text(env, paths), text(env, installed.optimizedDirectory), nullptr, loader); check(env);
        auto base = type(env, "dalvik/system/BaseDexClassLoader");
        auto listField = field(env, base, "pathList", "Ldalvik/system/DexPathList;");
        auto oldList = env->GetObjectField(loader, listField); check(env);
        auto newList = env->GetObjectField(extra, listField); check(env);
        dexpack::require(oldList && newList, "Android DEX path list is unavailable.");
        auto listClass = type(env, "dalvik/system/DexPathList");
        auto elementsField = field(env, listClass, "dexElements", "[Ldalvik/system/DexPathList$Element;");
        auto oldElements = static_cast<jobjectArray>(env->GetObjectField(oldList, elementsField)); check(env);
        auto newElements = static_cast<jobjectArray>(env->GetObjectField(newList, elementsField)); check(env);
        dexpack::require(oldElements && newElements, "Android DEX elements are unavailable.");
        jsize before = env->GetArrayLength(oldElements), added = env->GetArrayLength(newElements);
        dexpack::require(added == jsize(installed.dexPaths.size()), "Android could not load every packed DEX.");
        dexpack::require(before <= INT32_MAX-added, "Too many DEX elements.");
        auto combined = env->NewObjectArray(before+added, type(env, "dalvik/system/DexPathList$Element"), nullptr); check(env);
        for (jsize i = 0; i < before+added; ++i) {
            auto element = env->GetObjectArrayElement(i < before ? oldElements : newElements, i < before ? i : i-before); check(env);
            env->SetObjectArrayElement(combined, i, element); check(env); env->DeleteLocalRef(element);
        }
        auto global = env->NewGlobalRef(loader); check(env);
        try { prepared.push_back({global, installed.application}); } catch (...) { env->DeleteGlobalRef(global); throw; }
        env->SetObjectField(oldList, elementsField, combined);
        if (env->ExceptionCheck()) { prepared.pop_back(); env->DeleteGlobalRef(global); throw JavaException{}; }
        return prepared.back();
    }
    const Prepared& prepareInfo(JNIEnv* env, jobject loader, jobject info) {
        dexpack::require(info != nullptr, "ApplicationInfo is unavailable.");
        auto apk = static_cast<jstring>(get(env, info, "sourceDir", "Ljava/lang/String;"));
        auto data = static_cast<jstring>(get(env, info, "dataDir", "Ljava/lang/String;"));
        return prepare(env, loader, text(env, apk), text(env, data));
    }
    const Prepared& prepareContext(JNIEnv* env, jobject context) {
        auto cls = type(env, "android/content/Context");
        auto info = env->CallObjectMethod(context, method(env, cls, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;")); check(env);
        auto loader = env->CallObjectMethod(context, method(env, cls, "getClassLoader", "()Ljava/lang/ClassLoader;")); check(env);
        return prepareInfo(env, loader, info);
    }
    void replaceProviderContexts(JNIEnv* env, jobject thread, jobject application) {
        auto cls = env->GetObjectClass(thread); check(env);
        auto id = env->GetFieldID(cls, "mProviderMap", "Landroid/util/ArrayMap;");
        if (!id) {
            env->ExceptionClear(); id = env->GetFieldID(cls, "mProviderMap", "Ljava/util/HashMap;"); check(env);
        }
        auto providers = env->GetObjectField(thread, id); check(env);
        if (!providers) return;
        auto values = env->CallObjectMethod(providers, method(env, type(env, "java/util/Map"), "values", "()Ljava/util/Collection;")); check(env);
        auto iterator = env->CallObjectMethod(values, method(env, type(env, "java/util/Collection"), "iterator", "()Ljava/util/Iterator;")); check(env);
        auto iteratorClass = type(env, "java/util/Iterator");
        auto hasNext = method(env, iteratorClass, "hasNext", "()Z"), next = method(env, iteratorClass, "next", "()Ljava/lang/Object;");
        for (;;) {
            auto more = env->CallBooleanMethod(iterator, hasNext); check(env); if (!more) break;
            auto record = env->CallObjectMethod(iterator, next); check(env);
            if (record) {
                auto provider = get(env, record, "mLocalProvider", "Landroid/content/ContentProvider;");
                if (provider) { set(env, provider, "mContext", "Landroid/content/Context;", application); env->DeleteLocalRef(provider); }
                env->DeleteLocalRef(record);
            }
        }
    }
    void createApplication(JNIEnv* env, jobject shell) {
        if (originalApplication || creatingApplication) return;
        auto state = prepareContext(env, shell);
        creatingApplication = true;
        struct Reset { ~Reset() { creatingApplication = false; } } reset;
        auto thread = activityThread(env), bound = boundApplication(env, thread);
        auto loaded = get(env, bound, "info", "Landroid/app/LoadedApk;");
        dexpack::require(loaded != nullptr, "Loaded application is unavailable.");
        auto appInfo = get(env, bound, "appInfo", "Landroid/content/pm/ApplicationInfo;");
        auto loadedInfo = get(env, loaded, "mApplicationInfo", "Landroid/content/pm/ApplicationInfo;");
        auto name = text(env, state.application);
        set(env, appInfo, "className", "Ljava/lang/String;", name);
        set(env, loadedInfo, "className", "Ljava/lang/String;", name);
        set(env, loaded, "mApplication", "Landroid/app/Application;", nullptr);
        auto apps = get(env, thread, "mAllApplications", "Ljava/util/ArrayList;");
        env->CallBooleanMethod(apps, method(env, type(env, "java/util/ArrayList"), "remove", "(Ljava/lang/Object;)Z"), shell); check(env);
        auto cls = type(env, "android/app/LoadedApk");
        auto original = env->CallObjectMethod(loaded, method(env, cls, "makeApplication", "(ZLandroid/app/Instrumentation;)Landroid/app/Application;"), JNI_FALSE, nullptr); check(env);
        dexpack::require(original != nullptr, "Cannot create original Application.");
        set(env, thread, "mInitialApplication", "Landroid/app/Application;", original);
        replaceProviderContexts(env, thread, original);
        originalApplication = env->NewGlobalRef(original); check(env);
        env->CallVoidMethod(original, method(env, type(env, "android/app/Application"), "onCreate", "()V")); check(env);
    }
    template<class F> void invoke(JNIEnv* env, F action) {
        if (env->PushLocalFrame(96) < 0) return;
        try { std::lock_guard<std::recursive_mutex> guard(mutex); action(); }
        catch (const JavaException&) {}
        catch (const std::exception& error) {
            if (!env->ExceptionCheck()) { auto cls = env->FindClass("java/lang/IllegalStateException"); if (cls) env->ThrowNew(cls, error.what()); }
        }
        catch (...) { if (!env->ExceptionCheck()) { auto cls = env->FindClass("java/lang/IllegalStateException"); if (cls) env->ThrowNew(cls, "Shield initialization failed."); } }
        env->PopLocalFrame(nullptr);
    }
}
extern "C" JNIEXPORT void JNICALL Java_cn_beingyi_sckit_shield1_SubApp_prepare(JNIEnv* env, jclass, jobject loader, jstring apk, jstring data) {
    invoke(env, [&] { prepare(env, loader, text(env, apk), text(env, data)); });
}
extern "C" JNIEXPORT void JNICALL Java_cn_beingyi_sckit_shield1_SubApp_prepareFromRuntime(JNIEnv* env, jclass, jobject loader) {
    invoke(env, [&] {
        for (const auto& entry : prepared) if (env->IsSameObject(loader, entry.loader)) return;
        auto info = get(env, boundApplication(env, activityThread(env)), "appInfo", "Landroid/content/pm/ApplicationInfo;");
        prepareInfo(env, loader, info);
    });
}
extern "C" JNIEXPORT void JNICALL Java_cn_beingyi_sckit_shield1_SubApp_attach(JNIEnv* env, jclass, jobject context) {
    invoke(env, [&] { prepareContext(env, context); });
}
extern "C" JNIEXPORT void JNICALL Java_cn_beingyi_sckit_shield1_SubApp_create(JNIEnv* env, jclass, jobject shell) {
    invoke(env, [&] { createApplication(env, shell); });
}
