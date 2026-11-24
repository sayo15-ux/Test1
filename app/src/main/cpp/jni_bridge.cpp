#include "engine.hpp"
#include <jni.h>
#include <cctype>
#include <mutex>
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
static std::mutex sigKillV3Mutex;
static SignatureKillV3Options sigKillV3Options;
static std::mutex sigKillV4Mutex;
static SignatureKillV4Options sigKillV4Options;

extern "C" JNIEXPORT void JNICALL Java_io_dexpack_tool_NativeEngine_setSignatureKillV3Options(JNIEnv*env,jclass,jint flags,jstring redirection) {
    try {
        std::lock_guard<std::mutex> lock(sigKillV3Mutex);
        sigKillV3Options = SignatureKillV3Options();
        sigKillV3Options.flags = uint32_t(flags);
        sigKillV3Options.pmProxy = flags & 1;
        sigKillV3Options.earlyProvider = flags & 2;
        sigKillV3Options.patchSigningInfo = flags & 4;
        sigKillV3Options.replaceApkPath = flags & 8;
        sigKillV3Options.patchApplicationInfo = flags & 16;
        sigKillV3Options.basicsToSign = flags & 32;
        sigKillV3Options.debuggable = flags & 64;
        sigKillV3Options.fileRedirection = redirection ? utf8(fromJava(env, redirection)) : "default";
        if (sigKillV3Options.fileRedirection.empty()) sigKillV3Options.fileRedirection = "default";
    }
    catch(const std::exception&e) {
        error(env,e);
    }
}

extern "C" JNIEXPORT void JNICALL Java_io_dexpack_tool_NativeEngine_setSignatureKillV4Options(JNIEnv*env,jclass,jint flags) {
    try {
        std::lock_guard<std::mutex> lock(sigKillV4Mutex);
        sigKillV4Options = SignatureKillV4Options();
        sigKillV4Options.flags = uint32_t(flags);
        sigKillV4Options.pmProxy = flags & 1;
        sigKillV4Options.patchSigningInfo = flags & 2;
        sigKillV4Options.replaceApkPath = flags & 4;
        sigKillV4Options.patchApplicationInfo = flags & 8;
        sigKillV4Options.embedOriginalApk = flags & 16;
        sigKillV4Options.delegateOriginalApplication = flags & 32;
        sigKillV4Options.debuggable = flags & 64;
    }
    catch(const std::exception&e) {
        error(env,e);
    }
}

static std::string lowerAscii(std::string s){ for(char& c:s) c=(char)std::tolower((unsigned char)c); return s; }

extern "C" JNIEXPORT jobjectArray JNICALL Java_io_dexpack_tool_NativeEngine_archiveEntries(JNIEnv*env,jclass,jstring path) {
    try {
        dexpack::Archive a(utf8(fromJava(env,path)));
        std::vector<Text> values;
        values.reserve(a.entries.size());
        for(const auto& e:a.entries) {
            values.push_back(utf16(e.name + "|" + std::to_string(e.compressed) + "|" + std::to_string(e.size) + "|" + (dexpack::dexEntry(e.name)?"dex":"file")));
        }
        return strings(env, values);
    } catch(const std::exception&e) { error(env,e); return nullptr; }
}

extern "C" JNIEXPORT jobjectArray JNICALL Java_io_dexpack_tool_NativeEngine_dexSearch(JNIEnv*env,jclass,jstring path,jstring query) {
    try {
        dexpack::Archive a(utf8(fromJava(env,path)));
        std::string q=lowerAscii(utf8(fromJava(env,query)));
        std::vector<Text> out;
        size_t limit=500;
        auto push=[&](const std::string& s){ if(out.size()<limit) out.push_back(utf16(s)); };
        for(const auto& e:a.entries) {
            if(!dexpack::dexEntry(e.name)) continue;
            auto data=a.extract(e.name);
            auto model=dexpack::dex::read(data, true);
            for(const auto& c:model.classes) {
                std::string cn=utf8(c.type);
                std::string lcn=lowerAscii(cn);
                if(q.empty() || lcn.find(q)!=std::string::npos) push(e.name+"|class|"+cn+"||");
                for(const auto* g:{&c.direct,&c.virtuals}) for(const auto& m:*g) {
                    std::string mn=utf8(m->ref->text);
                    std::string sig=utf8(dexpack::dex::key(m->ref));
                    std::string l=lowerAscii(mn+" "+sig);
                    if(q.empty() || l.find(q)!=std::string::npos) push(e.name+"|method|"+cn+"|"+mn+"|"+sig);
                    if(!m->code) continue;
                    for(const auto& ins:m->code->instructions) {
                        if(ins.ref && ins.ref->kind==dexpack::dex::Kind::String) {
                            std::string sv=utf8(ins.ref->text);
                            std::string ls=lowerAscii(sv);
                            if(!q.empty() && ls.find(q)!=std::string::npos) push(e.name+"|string|"+cn+"|"+mn+"|"+sv);
                        }
                    }
                }
                if(out.size()>=limit) return strings(env,out);
            }
        }
        return strings(env,out);
    } catch(const std::exception&e) { error(env,e); return nullptr; }
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
        SignatureKillV3Options v3;
        {
            std::lock_guard<std::mutex> lock(sigKillV3Mutex);
            v3 = sigKillV3Options;
        }
        SignatureKillV4Options v4;
        {
            std::lock_guard<std::mutex> lock(sigKillV4Mutex);
            v4 = sigKillV4Options;
        }
        auto report=dexpack::protect(input,destination,mode,names,[&](const std::string&label,int percent) {
            if(!listener)return;if(percent==previous&&label==last)return;previous=percent;last=label;auto s=toJava(env,utf16(label));require(s!=nullptr,"Cannot create progress message.");env->CallVoidMethod(listener,progress,s,jint(percent));env->DeleteLocalRef(s);require(!env->ExceptionCheck(),"Processing cancelled.");
        }, {}, v3, v4);
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
