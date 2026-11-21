#include "engine.hpp"
#include <jni.h>
namespace {
    using namespace dexpack;
    Text fromJava(JNIEnv*env,jstring s) {
        require(s!=nullptr,"Missing text parameter.");
        auto n=env->GetStringLength(s);
        auto chars=env->GetStringChars(s,nullptr);
        require(chars!=nullptr,"Cannot read Java text.");
        Text result(reinterpret_cast<const char16_t*>(chars),size_t(n));
        env->ReleaseStringChars(s,chars);
        return result;
    }
    jstring toJava(JNIEnv*env,const Text&s) {
        require(s.size()<=size_t(std::numeric_limits<jsize>::max()),"Java string length overflow.");
        return env->NewString(reinterpret_cast<const jchar*>(s.data()),jsize(s.size()));
    }
    jobjectArray strings(JNIEnv*env,const std::vector<Text>&values) {
        require(values.size() <= size_t(std::numeric_limits<jsize>::max()), "Too many classes for an Android array.");
        auto cls=env->FindClass("java/lang/String");
        if(!cls)return nullptr;
        auto a=env->NewObjectArray(jsize(values.size()),cls,nullptr);
        env->DeleteLocalRef(cls);
        if(!a)return nullptr;
        for(size_t i=0;i<values.size();++i) {
            auto s=toJava(env,values[i]);
            if(!s)return nullptr;
            env->SetObjectArrayElement(a,jsize(i),s);
            env->DeleteLocalRef(s);
            if(env->ExceptionCheck())return nullptr;
        }
        return a;
    }
    void error(JNIEnv*env,const std::exception&e) {
        if(env->ExceptionCheck())return;
        auto cls=env->FindClass("java/io/IOException");
        if(cls) {
            env->ThrowNew(cls,e.what());
            env->DeleteLocalRef(cls);
        }
    }
}
extern "C" JNIEXPORT jobjectArray JNICALL Java_io_dexpack_tool_NativeEngine_inspect(JNIEnv*env,jclass,jstring path) {
    try {
        dexpack::Input input(utf8(fromJava(env,path)));
        const auto&i=input.info;
        return strings(env, {
            i.packageName,i.sharedUserId,utf16(std::to_string(i.minSdk)),utf16(std::to_string(i.targetSdk)),i.applicationName,i.factoryName
        });
    }
    catch(const std::exception&e) {
        error(env,e);
        return nullptr;
    }
}
extern "C" JNIEXPORT jobjectArray JNICALL Java_io_dexpack_tool_NativeEngine_classes(JNIEnv*env,jclass,jstring path) {
    try {
        return strings(env,dexpack::classes(dexpack::Input(utf8(fromJava(env,path)))));
    }
    catch(const std::exception&e) {
        error(env,e);
        return nullptr;
    }
}
extern "C" JNIEXPORT jlongArray JNICALL Java_io_dexpack_tool_NativeEngine_protect(JNIEnv*env,jclass,jstring source,jstring output,jint mode,jobjectArray selected,jobject listener) {
    try {
        Input input(utf8(fromJava(env,source)));
        auto destination=utf8(fromJava(env,output));
        std::set<Text>names;
        if(selected)for(jsize i=0;i<env->GetArrayLength(selected);++i) {
            auto s=static_cast<jstring>(env->GetObjectArrayElement(selected,i));
            names.insert(fromJava(env,s));
            env->DeleteLocalRef(s);
        }
        jmethodID progress=nullptr;
        if(listener) {
            auto cls=env->GetObjectClass(listener);
            progress=env->GetMethodID(cls,"onProgress","(Ljava/lang/String;I)V");
            env->DeleteLocalRef(cls);
            require(progress!=nullptr,"Progress callback is missing.");
        }
        int previous=-1;
        std::string last;
        auto report=dexpack::protect(input,destination,mode,names,[&](const std::string&label,int percent) {
            if(!listener)return;if(percent==previous&&label==last)return;previous=percent;last=label;auto s=toJava(env,utf16(label));require(s!=nullptr,"Cannot create progress message.");env->CallVoidMethod(listener,progress,s,jint(percent));env->DeleteLocalRef(s);require(!env->ExceptionCheck(),"Processing cancelled.");
        });
        jlong values[] {
            jlong(report.classes),jlong(report.literals),jlong(report.staticFields),jlong(report.uniqueStrings),jlong(report.classTables),jlong(report.methodsReframed),jlong(report.highRegisterSites),jlong(report.bridges)
        };
        auto result=env->NewLongArray(8);
        if(result)env->SetLongArrayRegion(result,0,8,values);
        return result;
    }
    catch(const std::exception&e) {
        error(env,e);
        return nullptr;
    }
}
