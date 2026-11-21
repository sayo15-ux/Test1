#include "engine.hpp"
namespace dexpack {
    static const std::string ASSET="assets/ScKit_shield_v1.dex";
    static const std::vector<std::string> ABIS {
        "arm64-v8a","armeabi-v7a","x86_64","x86"
    };
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
            require(!archive.find("lib/"+abi+"/libScKitShieldV1.so"),"Protection library name collision.");
        }
    }
    std::vector<Text> classes(const Input&input) {
        std::set<Text>seen;
        for(const auto&name:input.dexNames) {
            auto data=input.archive.extract(name);
            for(const auto&t:dex::classNames(data)) {
                require(seen.insert(t).second,"This APK defines a class twice.");
                require(t.rfind(u"Lcn/beingyi/sckit/shield1/",0)!=0,"This APK already contains a shield loader.");
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
    StringReport protect(const Input&input,const std::string&output,int mode,const std::set<Text>&selected,const Progress&progress,std::optional<int64_t>fixedClock) {
        require(mode>=0&&mode<=3,"Unknown protection mode.");
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
            for(const auto&abi:input.abis)replacements["lib/"+abi+"/libScKitShieldV1.so"]= {
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
            // Signature Killer: replace in-app verification methods with success stubs.
            for(size_t i=0;i<input.dexNames.size();++i) {
                const auto&name=input.dexNames[i];
                auto result=killSignatures(input.archive.extract(name),[&](const std::string&s,int n) {
                    step(s,15+int((i*100+n)*50/(input.dexNames.size()*100)));
                });
                report.classes+=result.report.classes;
                report.literals+=result.report.methods;
                report.staticFields+=result.report.sites;
                if(result.changed)replacements[name]= {
                    std::move(result.bytes),false
                };
            }
            require(report.literals,"No supported signature verification code was found in this APK.");
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
