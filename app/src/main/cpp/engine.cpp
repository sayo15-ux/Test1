#include "engine.hpp"
#include "fancy_payloads.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
namespace dexpack {
    static const std::string ASSET="assets/Fallen_shield_v1.dex";
    static const std::string SIGV2_ASSET="assets/Fallen_sigkill2_original.apk";
    static const std::vector<std::string> ABIS {
        "arm64-v8a","armeabi-v7a","x86_64","x86"
    };
    static size_t readUleb(const Bytes& b,size_t p,uint32_t&v) {
        v=0;
        unsigned shift=0;
        for(;;) {
            require(p<b.size()&&shift<32,"Invalid DEX ULEB128.");
            uint8_t c=b[p++];
            v|=uint32_t(c&0x7f)<<shift;
            if(!(c&0x80))return p;
            shift+=7;
        }
    }
    static void writeUleb(Bytes& b,size_t p,uint32_t v,size_t len) {
        std::vector<uint8_t>bytes;
        do {
            uint8_t c=uint8_t(v&0x7f);
            v>>=7;
            bytes.push_back(v?uint8_t(c|0x80):c);
        } while(v);
        require(bytes.size()<=len,"Invalid DEX ULEB128 width.");
        while(bytes.size()<len) {
            bytes.back()|=0x80;
            bytes.push_back(0);
        }
        for(size_t i=0;i<len;++i)b[p+i]=bytes[i];
    }
    void patchFinalMethods(Bytes& b,uint32_t classDefOff,const std::set<std::string>&names) {
        uint32_t methodCount=get32(b,88),methodOff=get32(b,92);
        require(methodOff,"Invalid DEX method table.");
        uint32_t classIdx=get32(b,classDefOff);
        std::set<uint32_t>targets;
        auto readString=[&](uint32_t index) {
            require(index<get32(b,56),"Invalid DEX string index.");
            uint32_t stringOff=get32(b,size_t(get32(b,60))+4*size_t(index));
            uint32_t utf16Size=0;
            auto p=readUleb(b,stringOff,utf16Size);
            auto start=p;
            while(p<b.size()&&b[p])++p;
            require(p<b.size(),"Invalid DEX string data.");
            return std::string(reinterpret_cast<const char*>(b.data()+start),p-start);
        };
        for(uint32_t i=0;i<methodCount;++i) {
            size_t o=size_t(methodOff)+8*size_t(i);
            if(get16(b,o)!=classIdx)continue;
            if(names.count(readString(get32(b,o+4))))targets.insert(i);
        }
        require(!targets.empty(),"Original application lifecycle methods not found.");
        uint32_t classData=get32(b,classDefOff+24);
        require(classData,"Missing DEX class data.");
        uint32_t staticFields=0,instanceFields=0,direct=0,virt=0;
        size_t p=classData;
        p=readUleb(b,p,staticFields);
        p=readUleb(b,p,instanceFields);
        p=readUleb(b,p,direct);
        p=readUleb(b,p,virt);
        for(uint32_t i=0;i<staticFields+instanceFields;++i) {
            uint32_t ignore=0;
            p=readUleb(b,p,ignore);
            p=readUleb(b,p,ignore);
        }
        auto patch=[&](uint32_t count) {
            uint32_t index=0;
            for(uint32_t i=0;i<count;++i) {
                uint32_t diff=0;
                p=readUleb(b,p,diff);
                index+=diff;
                size_t flagsPos=p;
                uint32_t flags=0;
                p=readUleb(b,p,flags);
                size_t flagsEnd=p;
                uint32_t code=0;
                p=readUleb(b,p,code);
                if(targets.count(index)&&(flags&0x10))writeUleb(b,flagsPos,flags&~0x10u,flagsEnd-flagsPos);
            }
        };
        patch(direct);
        patch(virt);
    }
    Input::Input(const std::string&path):archive(path),manifest(archive.extract("AndroidManifest.xml")),info(inspectManifest(manifest)) {
        require(!archive.find(ASSET),"This APK is already shielded.");
        for(const auto&e:archive.entries)if(dexEntry(e.name))dexNames.push_back(e.name);
        std::sort(dexNames.begin(),dexNames.end(),[](const std::string&a,const std::string&b) {
            if (a == "classes.dex") return b != a;
            if (b == "classes.dex") return false;
            return a.size() != b.size() ? a.size() < b.size() : a < b;
        });
        require(!dexNames.empty()&&dexNames[0]=="classes.dex","This APK has no classes.dex.");
        for(size_t i=0;i<dexNames.size();++i)require(dexNames[i]==(i?"classes"+std::to_string(i+1)+".dex":"classes.dex"),"Non-contiguous DEX files.");
        std::set<std::string>present;
        for(const auto&e:archive.entries)if(e.name.rfind("lib/",0)==0&&e.name.size()>3&&e.name.substr(e.name.size()-3)==".so") {
            auto slash=e.name.find('/',4);
            if(slash!=std::string::npos)present.insert(e.name.substr(4,slash-4));
        }
        for(const auto&abi:ABIS) {
            if(present.empty()||present.count(abi))abis.push_back(abi);
            require(!archive.find("lib/"+abi+"/libFallenShieldV1.so"),"Protection library name collision.");
        }
    }
    std::vector<Text> classes(const Input&input) {
        std::set<Text>seen;
        for(const auto&name:input.dexNames) {
            auto data=input.archive.extract(name);
            for(const auto&t:dex::classNames(data)) {
                require(seen.insert(t).second,"This APK defines a class twice.");
                require(t.rfind(u"Lcn/beingyi/fallen/shield1/",0)!=0,"This APK already contains a shield loader.");
            }
        }
        return {
            seen.begin(),seen.end()
        };
    }
    static std::string meta(const std::string&s) {
        auto b=ascii(s);
        for(auto&v:b)v^=56;
        return hex(b);
    }
    static Bytes asset(const Input&input,const Progress&progress) {
        std::vector<std::pair<std::string,Bytes>>entries;
        std::string names;
        for(size_t i=0;i<input.dexNames.size();++i) {
            const auto&name=input.dexNames[i];
            auto data=input.archive.extract(name);
            validateDex(data);
            entries.emplace_back(name,std::move(data));
            if(i)names+=',';
            names+=name;
            if(progress)progress("Packing DEX",15+int((i+1)*20/input.dexNames.size()));
        }
        for(const auto&p:std::vector<std::pair<std::string,std::string>> {
            {
                "dexNames",names
            }, {
                "originApplicationName",utf8(input.info.applicationName)
            }, {
                "existApplicationClass",input.info.hasApplication?"1":"0"
            }
        })entries.emplace_back(meta(p.first),ascii(meta(p.second)));
        require(entries.size()<65536,"Shield payload index overflow.");
        uint64_t off=10,total;
        for(const auto&e:entries) {
            require(e.first.size()<=65535,"Shield entry name too long.");
            off+=14+e.first.size();
        }
        total=off;
        for(const auto&e:entries)total+=e.second.size();
        auto stub=payload::stub();
        require(stub.size()==416&&total+stub.size()<NONE,"Shield payload exceeds the DEX format.");
        Writer w;
        w.bytes(stub).u32(0xef0051).u32(uint32_t(total)).u16(narrow(entries.size()));
        for(const auto&e:entries) {
            w.u32(0xef0061).u16(narrow(e.first.size())).u32(uint32_t(off)).u32(narrow(e.second.size())).bytes(ascii(e.first));
            off+=e.second.size();
        }
        for(const auto&e:entries)w.bytes(e.second);
        fixDex(w.b);
        return w.b;
    }
    StringReport protect(const Input&input,const std::string&output,int mode,const std::set<Text>&selected,const Progress&progress,std::optional<int64_t>fixedClock,const SignatureKillV3Options& sigV3,const SignatureKillV4Options& sigV4,const Text& signatureDigest) {
        require(mode>=0&&mode<=6,"Unknown protection mode.");
        auto step=[&](const std::string&s,int n) {
            if(progress)progress(s,n);
        };
        step("Analyzing APK",5);
        auto available=classes(input);
        std::set<Text>names(available.begin(),available.end());
        std::map<std::string,Replacement>replacements;
        std::set<std::string>remove;
        StringReport report;
        if(mode==0) {
            require(!input.abis.empty(),"This APK has no compatible ARM/x86 libraries.");
            replacements[ASSET]= {
                asset(input,progress),false
            };
            auto shell=dex::read(payload::shell());
            dex::rename(shell,u"io.dexpack.template.OriginalApplication",input.info.applicationName);
            dex::rename(shell,u"io.dexpack.template.OriginalFactory",input.info.factoryName);
            replacements["classes.dex"]= {
                dex::write(shell),false
            };
            replacements["AndroidManifest.xml"]= {
                shieldManifest(input.manifest),false
            };
            for(const auto&name:input.dexNames)remove.insert(name);
            for(const auto&abi:input.abis)replacements["lib/"+abi+"/libFallenShieldV1.so"]= {
                payload::library(abi),true
            };
            for(const auto&e:input.archive.entries)if(e.name.rfind("lib/",0)==0) {
                auto slash=e.name.find('/',4);
                if(slash!=std::string::npos&&std::find(input.abis.begin(),input.abis.end(),e.name.substr(4,slash-4))==input.abis.end())remove.insert(e.name);
            }
            auto resources=input.archive.find("resources.arsc");
            if(resources&&resources->method!=0)replacements[resources->name]= {
                input.archive.extract(*resources),true
            };
            report.classes=available.size();
        }
        else if(mode==3) {
            const Text helper=u"Lio/dexpack/sig/SignatureKiller;";
            SignatureOptions options;
            options.className=helper;
            options.applicationName=input.info.applicationName;
            options.packageName=input.info.packageName;
            options.classes=names;
            auto result=killSignatures(input.archive,options,[&](const std::string&s,int n) {
                step(s,15+n/2);
            });
            report.classes+=result.report.classes;
            report.literals+=result.report.methods;
            report.staticFields+=result.report.sites;
            auto isPm=[&](const dex::Ref& ref){
                if(!ref||ref->kind!=dex::Kind::Method) return false;
                auto n=ref->text, o=ref->owner;
                bool pm=(o==u"Landroid/content/pm/PackageManager;"||o==u"Landroid/app/ApplicationPackageManager;");
                return pm && (n==u"getPackageInfo"||n==u"getPackageArchiveInfo");
            };
            auto hookRef=[&](const dex::Ref& ref)->dex::Ref{
                const Text PM=u"Landroid/content/pm/PackageManager;",PI=u"Landroid/content/pm/PackageInfo;",S=u"Ljava/lang/String;";
                if(ref->text==u"getPackageArchiveInfo") return dex::method(helper,u"$getPackageArchiveInfo",PI,{PM,S,u"I"});
                if(ref->proto && ref->proto->params.size()==2 && ref->proto->params[1]==u"Landroid/content/pm/PackageManager$PackageInfoFlags;")
                    return dex::method(helper,u"$getPackageInfo",PI,{PM,S,u"Landroid/content/pm/PackageManager$PackageInfoFlags;"});
                return dex::method(helper,u"$getPackageInfo",PI,{PM,S,u"I"});
            };
            auto hasPmSigCall=[&](const Bytes& data)->bool{
                if(data.size()<112) return false;
                auto u16=[&](size_t o)->uint32_t{ return o+2<=data.size()?uint32_t(data[o])|(uint32_t(data[o+1])<<8):0u; };
                auto u32=[&](size_t o)->uint32_t{ return o+4<=data.size()?uint32_t(data[o])|(uint32_t(data[o+1])<<8)|(uint32_t(data[o+2])<<16)|(uint32_t(data[o+3])<<24):0u; };
                uint32_t sc=u32(56), so=u32(60), tc=u32(64), to=u32(68), mc=u32(88), mo=u32(92);
                if(uint64_t(so)+uint64_t(sc)*4>data.size()||uint64_t(to)+uint64_t(tc)*4>data.size()||uint64_t(mo)+uint64_t(mc)*8>data.size()) return true;
                auto strEq=[&](uint32_t idx,const char* s,size_t n)->bool{
                    if(idx>=sc) return false;
                    size_t p=u32(so+idx*4); if(p>=data.size()) return false;
                    uint32_t len=0,shift=0;
                    for(int i=0;i<5&&p<data.size();++i){ uint8_t b=data[p++]; len|=uint32_t(b&0x7f)<<shift; if(!(b&0x80)) break; shift+=7; }
                    return len==n && p+n<=data.size() && std::memcmp(data.data()+p,s,n)==0;
                };
                std::vector<uint32_t> nameIdxs; nameIdxs.reserve(2);
                for(uint32_t i=0;i<sc;++i){
                    size_t p=u32(so+i*4); if(p>=data.size()) continue;
                    uint32_t len=0,shift=0; size_t q=p;
                    for(int k=0;k<5&&q<data.size();++k){ uint8_t b=data[q++]; len|=uint32_t(b&0x7f)<<shift; if(!(b&0x80)) break; shift+=7; }
                    if((len==14 && q+14<=data.size() && std::memcmp(data.data()+q,"getPackageInfo",14)==0) ||
                       (len==21 && q+21<=data.size() && std::memcmp(data.data()+q,"getPackageArchiveInfo",21)==0)) nameIdxs.push_back(i);
                }
                if(nameIdxs.empty()) return false;
                std::vector<uint32_t> ownerIdxs; ownerIdxs.reserve(2);
                for(uint32_t i=0;i<tc;++i){
                    uint32_t sidx=u32(to+i*4);
                    if(strEq(sidx,"Landroid/content/pm/PackageManager;",35) || strEq(sidx,"Landroid/app/ApplicationPackageManager;",39)) ownerIdxs.push_back(i);
                }
                if(ownerIdxs.empty()) return false;
                for(uint32_t i=0;i<mc;++i){
                    size_t o=mo+i*8; uint32_t classIdx=u16(o), nameIdx=u32(o+4);
                    bool on=false,nn=false;
                    for(auto x:ownerIdxs) if(x==classIdx){on=true;break;} if(!on) continue;
                    for(auto x:nameIdxs) if(x==nameIdx){nn=true;break;} if(nn) return true;
                }
                return false;
            };
            step("Prefiltering DEX for signature calls", 32);
            struct DexJob { size_t idx; std::string name; Bytes data; Bytes out; uint64_t hits=0; bool changed=false; std::string err; };
            std::vector<DexJob> jobs;
            for(size_t i=0;i<input.dexNames.size();++i) {
                const auto&name=input.dexNames[i];
                step("Prefilter " + name, 32 + int(i * 18 / std::max<size_t>(1, input.dexNames.size())));
                auto data=input.archive.extract(name);
                if(hasPmSigCall(data)) jobs.push_back({i,name,std::move(data),{},0,false,{}});
            }
            step("Patching " + std::to_string(jobs.size()) + " candidate DEX", 52);
            std::atomic<size_t> next{0}, done{0};
            auto worker=[&](){
                for(;;){
                    size_t j=next.fetch_add(1);
                    if(j>=jobs.size()) break;
                    auto& job=jobs[j];
                    try {
                        auto model=dex::read(job.data, true, false);
                        bool changed=false; uint64_t hits=0;
                        for(auto& cls:model.classes) {
                            for(auto* group:{&cls.direct,&cls.virtuals}) for(auto& m:*group) {
                                if(!m->code) continue;
                                for(auto& ins:m->code->instructions) {
                                    if(!ins.ref || !isPm(ins.ref)) continue;
                                    bool kind35=(ins.op>=0x6e&&ins.op<=0x72);
                                    bool kind3r=(ins.op>=0x74&&ins.op<=0x78);
                                    if(!kind35&&!kind3r) continue;
                                    ins.ref=hookRef(ins.ref);
                                    ins.op=kind35?0x71:0x77;
                                    if(!ins.units.empty()) ins.units[0]=uint16_t((ins.units[0]&0xff00u)|ins.op);
                                    changed=true; hits++;
                                }
                            }
                        }
                        if(changed) job.out=dex::write(model);
                        job.changed=changed; job.hits=hits;
                    } catch(const std::exception& e) { job.err=e.what(); }
                    catch(...) { job.err="unknown error"; }
                    done.fetch_add(1);
                }
            };
            unsigned workers=std::min<unsigned>(4u, std::max<unsigned>(1u, std::thread::hardware_concurrency()));
            workers=std::min<unsigned>(workers, (unsigned)jobs.size());
            if(workers<=1) worker();
            else {
                std::vector<std::thread> ts;
                for(unsigned t=0;t<workers;++t) ts.emplace_back(worker);
                while(done.load()<jobs.size()) { std::this_thread::sleep_for(std::chrono::milliseconds(120)); step("Patching candidate DEX", 52 + int(done.load() * 28 / std::max<size_t>(1,jobs.size()))); }
                for(auto& t:ts) t.join();
            }
            for(auto& job:jobs) {
                if(!job.err.empty()) throw std::runtime_error(job.name + ": " + job.err);
                if(job.changed) { replacements[job.name]={std::move(job.out),false}; report.uniqueStrings+=job.hits; }
            }
            step("Writing signature helper", 82);
            replacements["classes"+std::to_string(input.dexNames.size()+1)+".dex"]= {
                std::move(result.bytes),false
            };
        }
        else if(mode==4) {
            require(!input.archive.find(SIGV2_ASSET),"Signature Kill v2 asset collision.");
            const Text helper=u"Lio/dexpack/sigkill2/ProxyApplication;";
            auto appDesc=u"L"+input.info.applicationName+u";";
            for(auto& c:appDesc) if(c==u'.') c=u'/';
            for(size_t i=0;i<input.dexNames.size();++i) {
                const auto&name=input.dexNames[i];
                auto data=input.archive.extract(name);
                auto model=dex::read(data);
                bool changed=false;
                for(auto& cls:model.classes) if(cls.type==appDesc && (cls.flags&0x10)) { cls.flags&=~0x10u; changed=true; }
                if(changed) replacements[name]={dex::write(model),false};
            }
            SignatureOptions options;
            options.className=helper;
            options.applicationName=input.info.applicationName;
            options.packageName=input.info.packageName;
            options.originalApkAsset=utf16(SIGV2_ASSET);
            options.classes=names;
            auto result=killSignaturesV2(input.archive,options,[&](const std::string&s,int n) {
                step(s,15+n/2);
            });
            report.classes+=result.report.classes;
            report.literals+=result.report.methods;
            report.staticFields+=result.report.sites;
            // Inject helper into primary DEX for maximum compatibility.
            auto helperModel = dex::read(result.bytes);
            for (auto& c : helperModel.classes)
                for (auto* g : {&c.direct, &c.virtuals})
                    for (auto& m : *g) if (m->code) m->code->debug.reset();
            // put helper in its own dex like sigfall (classes2.dex or next available)
            std::string helperDex="classes2.dex";
            if (input.archive.find(helperDex) || replacements.count(helperDex)) {
                for(int i=2;i<999;++i){ std::string n=i==1?"classes.dex":"classes"+std::to_string(i)+".dex"; if(!input.archive.find(n)&&!replacements.count(n)){helperDex=n;break;} }
            }
            replacements[helperDex] = {dex::write(helperModel), false};
            replacements["AndroidManifest.xml"]= {signatureKillerManifest(input.manifest,helper),false};
            replacements[SIGV2_ASSET]= {readFile(input.archive.path()),true};
        }
        else if(mode==5) {
            require(!input.archive.find(SIGV2_ASSET),"Signature Kill v3 asset collision.");
            const Text helper=u"Lio/dexpack/sigkill3/ProxyApplication;";
            auto appDesc=u"L"+input.info.applicationName+u";";
            for(auto& c:appDesc) if(c==u'.') c=u'/';
            for(size_t i=0;i<input.dexNames.size();++i) {
                const auto&name=input.dexNames[i];
                auto data=input.archive.extract(name);
                auto model=dex::read(data);
                bool changed=false;
                for(auto& cls:model.classes) if(cls.type==appDesc && (cls.flags&0x10)) { cls.flags&=~0x10u; changed=true; }
                if(changed) replacements[name]={dex::write(model),false};
            }
            SignatureOptions options;
            options.className=helper;
            options.applicationName=input.info.applicationName;
            options.packageName=input.info.packageName;
            options.originalApkAsset=utf16(SIGV2_ASSET);
            options.classes=names;
            options.v3=sigV3;
            auto result=killSignaturesV3(input.archive,options,[&](const std::string&s,int n) {
                step(s,15+n/2);
            });
            report.classes+=result.report.classes;
            report.literals+=result.report.methods;
            report.staticFields+=result.report.sites;
            auto helperModel = dex::read(result.bytes);
            for (auto& c : helperModel.classes)
                for (auto* g : {&c.direct, &c.virtuals})
                    for (auto& m : *g) if (m->code) m->code->debug.reset();
            // put helper in its own dex like sigfall (classes2.dex or next available)
            std::string helperDex="classes2.dex";
            if (input.archive.find(helperDex) || replacements.count(helperDex)) {
                for(int i=2;i<999;++i){ std::string n=i==1?"classes.dex":"classes"+std::to_string(i)+".dex"; if(!input.archive.find(n)&&!replacements.count(n)){helperDex=n;break;} }
            }
            replacements[helperDex] = {dex::write(helperModel), false};
            replacements["AndroidManifest.xml"]= {signatureKillerManifestV3(input.manifest,helper,sigV3.earlyProvider,sigV3.debuggable),false};
            if (sigV3.replaceApkPath || sigV3.patchApplicationInfo) {
                replacements[SIGV2_ASSET]= {readFile(input.archive.path()),true};
            }
        }
        else if(mode==6) {
            static const std::string SIGV4_ASSET="fancy/origin.apk";
            static const std::string SIGV4_LIB64="fancy/lib/arm64.so";
            static const std::string SIGV4_LIB32="fancy/lib/arm.so";
            require(!input.archive.find(SIGV4_ASSET),"SigFall asset collision.");
            require(!input.archive.find(SIGV4_LIB64),"SigFall native library collision.");
            require(!input.archive.find(SIGV4_LIB32),"SigFall native library collision.");
            const Text helper=sigV4.cleanRoom?u"Lsigfall/component/SigFallApplication;":u"Lfancybypass/component/FancyApplication;";
            const Text factory=sigV4.cleanRoom?u"Lsigfall/component/SigFallAppFactory;":u"Lfancybypass/component/FancyAppFactory;";
            auto appDesc=u"L"+input.info.applicationName+u";";
            for(auto& c:appDesc) if(c==u'.') c=u'/';
            for(size_t i=0;i<input.dexNames.size();++i) {
                const auto&name=input.dexNames[i];
                auto data=input.archive.extract(name);
                auto model=dex::read(data);
                uint32_t classCount=get32(data,96);
                uint32_t classDefs=get32(data,100);
                require(classDefs&&classCount==model.classes.size(),"Invalid DEX class table.");
                bool changed=false;
                for(size_t j=0;j<model.classes.size();++j) {
                    const auto&cls=model.classes[j];
                    if(cls.type!=appDesc)continue;
                    if(cls.flags&0x10) {
                        size_t off=size_t(classDefs)+32*j+4;
                        require(off+4<=data.size(),"Invalid DEX class entry.");
                        put32(data,off,get32(data,off)&~0x10u);
                        changed=true;
                    }
                    patchFinalMethods(data,size_t(classDefs)+32*j,{"attachBaseContext","onCreate"});
                    changed=true;
                }
                if(changed) {
                    fixDex(data);
                    replacements[name]={data,false};
                }
            }
            SignatureOptions options;
            options.className=helper;
            options.factoryName=factory;
            options.applicationName=input.info.applicationName;
            options.packageName=input.info.packageName;
            options.originalApkAsset=utf16(SIGV4_ASSET);
            options.classes=names;
            options.v4=sigV4;
            if (sigV4.cleanRoom) {
                options.v4.embedOriginalApk=true;
                options.v4.replaceApkPath=true;
                options.v4.patchApplicationInfo=true;
            }
            auto result=killSignaturesV4(input.archive,options,[&](const std::string&s,int n) {
                step(s,15+n/2);
            });
            report.classes+=result.report.classes;
            report.literals+=result.report.methods;
            report.staticFields+=result.report.sites;
            std::string helperDexName = "classes3.dex";
            for (int index = 1;; ++index) {
                std::string candidate = index == 1 ? "classes.dex" : "classes" + std::to_string(index) + ".dex";
                if (!input.archive.find(candidate)) {
                    helperDexName = candidate;
                    break;
                }
            }
            if (!sigV4.cleanRoom) {
                auto nativeHelper = dex::read(fancy::referenceDex());
                dex::rename(nativeHelper, u"Lorg/clipbox/player/ClipBoxApplication;", appDesc);
                result.bytes = dex::write(nativeHelper);
                require(dex::classNames(result.bytes).size() > 50, "SigFall native helper patch failed.");
            }
            replacements[helperDexName] = {result.bytes, false};
            replacements["AndroidManifest.xml"]= {signatureKillerManifestV4(input.manifest,helper,input.info.applicationName,factory,sigV4.debuggable),false};
            {
                auto manifestInfo=inspectManifest(replacements["AndroidManifest.xml"].data);
                if (sigV4.cleanRoom) {
                    require(manifestInfo.applicationName==u"sigfall.component.SigFallApplication","SigFall manifest application patch failed.");
                    require(manifestInfo.factoryName==u"sigfall.component.SigFallAppFactory","SigFall manifest factory patch failed.");
                } else {
                    require(manifestInfo.applicationName==u"fancybypass.component.FancyApplication","SigFall manifest application patch failed.");
                    require(manifestInfo.factoryName==u"fancybypass.component.FancyAppFactory","SigFall manifest factory patch failed.");
                }
            }
            if (options.v4.embedOriginalApk || options.v4.replaceApkPath || options.v4.patchApplicationInfo) {
                step("Embedding original APK with shared ZIP data",58);
                replacements[SIGV4_ASSET]= {readFile(input.archive.path()),true,true};
            }
            {
                const char* msg="Placing some dex files here can be dynamically loaded\n";
                replacements["fancy/dex/README.txt"] = {Bytes(msg,msg+54), false};
            }
            replacements[SIGV4_LIB64] = {sigV4.cleanRoom?fancy::ownLibrary("arm64"):fancy::library("arm64"), true};
            replacements[SIGV4_LIB32] = {sigV4.cleanRoom?fancy::ownLibrary("arm"):fancy::library("arm"), true};
        }
        else {
            require(!selected.empty(),"Select at least one class.");
            for(const auto&c:selected)require(names.count(c),"Class selection belongs to another APK.");
            StringContext ctx;
            ctx.prepare(mode,names);
            if(fixedClock)ctx.millis=[fixedClock] {
                return *fixedClock;
            };
            require(!names.count(ctx.owner),"Generated helper class collision.");
            for(size_t i=0;i<input.dexNames.size();++i) {
                const auto&name=input.dexNames[i];
                auto result=transformStrings(input.archive.extract(name),mode,selected,ctx,[&](const std::string&s,int n) {
                    step(s,15+int((i*100+n)*50/(input.dexNames.size()*100)));
                });
                report+=result.report;
                if(result.changed)replacements[name]= {
                    std::move(result.bytes),false
                };
            }
            require(report.literals||report.staticFields,"Selected classes contain no supported non-empty string literals.");
            if(input.info.minSdk<21) {
                auto helper=stringHelper(mode,ctx);
                auto it=replacements.find("classes.dex");
                auto primary=dex::read(it==replacements.end()?input.archive.extract("classes.dex"):it->second.data);
                require(helper.handles.empty()&&helper.callsites.empty(),"Unexpected helper references.");
                primary.classes.insert(primary.classes.end(),helper.classes.begin(),helper.classes.end());
                replacements["classes.dex"]= {
                    dex::write(primary),false
                };
            }
            else replacements["classes"+std::to_string(input.dexNames.size()+1)+".dex"]= {
                stringHelperDex(mode,ctx),false
            };
        }
        step("Building APK",70);
        writeArchive(input.archive,output,replacements,remove,[&] {
            step("Building APK",75);
        });
        step("Ready to sign",80);
        return report;
    }
}
