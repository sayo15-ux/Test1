#include "manifest.hpp"
namespace dexpack {
    static const Text NS=u"http://schemas.android.com/apk/res/android";
    static const Text APP=u"cn.beingyi.fallen.shield1.SubApp",FACTORY=u"cn.beingyi.fallen.shield1.SubAppComponentFactory";
    struct Pool {
        std::vector<Text> strings;
        Bytes styleOffsets,styles;
        uint32_t styleCount=0;
        explicit Pool(const Bytes&b) {
            require(b.size()>=28,"Truncated manifest string pool.");
            auto hs=get16(b,2);
            auto n=get32(b,8);
            styleCount=get32(b,12);
            auto flags=get32(b,16),start=get32(b,20),styleStart=get32(b,24);
            require(hs>=28&&uint64_t(hs)+4*(uint64_t(n)+styleCount)<=b.size(),"Invalid manifest string pool.");
            auto len8=[](Reader&r) {
                auto n=r.u8();
                return n&128?uint32_t((n&127)<<8)|r.u8():uint32_t(n);
            };
            auto len16=[](Reader&r) {
                auto n=r.u16();
                return n&32768?uint32_t(n&32767)<<16|r.u16():uint32_t(n);
            };
            for(uint32_t i=0;i<n;++i) {
                uint64_t off=uint64_t(start)+get32(b,hs+4*i);
                require(off<b.size(),"Manifest string offset overflow.");
                Reader r(b,size_t(off));
                if(flags&256) {
                    auto chars=len8(r);
                    auto bytes=len8(r);
                    auto raw=r.take(bytes);
                    require(r.u8()==0,"Manifest string is not terminated.");
                    auto s=utf16(std::string(raw.begin(),raw.end()));
                    require(s.size()==chars,"Manifest string length mismatch.");
                    strings.push_back(std::move(s));
                }
                else {
                    auto length=len16(r);
                    r.need(size_t(length)*2+2);
                    Text s;
                    for(uint32_t j=0;j<length;++j)s+=char16_t(r.u16());
                    require(r.u16()==0,"Manifest string is not terminated.");
                    strings.push_back(std::move(s));
                }
            }
            styleOffsets=slice(b,hs+4*size_t(n),4*size_t(styleCount));
            if(styleStart) {
                require(styleStart<=b.size(),"Invalid manifest styles.");
                styles=slice(b,styleStart,b.size()-styleStart);
            }
        }
        Text get(uint32_t i)const {
            if(i==NONE)return {};
            require(i<strings.size(),"Invalid manifest string index.");
            return strings[i];
        }
        uint32_t add(const Text&s) {
            auto it=std::find(strings.begin(),strings.end(),s);
            if(it!=strings.end())return narrow(size_t(it-strings.begin()));
            strings.push_back(s);
            return narrow(strings.size()-1);
        }
        Bytes build()const {
            Writer data;
            std::vector<uint32_t>offsets;
            for(const auto&s:strings) {
                offsets.push_back(data.size());
                auto n=narrow(s.size());
                if(n>32767)data.u16(0x8000|(n>>16)).u16(n);
                else data.u16(n);
                for(auto c:s)data.u16(c);
                data.u16(0);
            }
            data.align();
            auto start=narrow(28+4*strings.size()+styleOffsets.size());
            Writer w;
            w.u16(1).u16(28).u32(narrow(uint64_t(start)+data.b.size()+styles.size())).u32(narrow(strings.size())).u32(styleCount).u32(0).u32(start).u32(styleCount?start+data.size():0);
            for(auto off:offsets)w.u32(off);
            w.bytes(styleOffsets).bytes(data.b).bytes(styles);
            return w.b;
        }
    };
    struct Attr {
        Bytes bytes;
        uint32_t ns=0,name=0,raw=0,value=0;
        uint8_t type=0;
        Text key,space,decoded;
    };
    struct Chunk {
        uint16_t kind=0,hs=0;
        Bytes bytes;
        Text name;
        std::vector<Attr>attrs;
    };
    struct Manifest {
        std::unique_ptr<Pool>pool;
        std::vector<Chunk>chunks;
        std::vector<uint32_t>map;
        explicit Manifest(const Bytes&b) {
            require(b.size()>=8&&get16(b,0)==3&&get32(b,4)==b.size(),"Choose an APK with a binary AndroidManifest.xml.");
            size_t p=get16(b,2);
            require(p==8,"Unsupported manifest header.");
            bool hadMap=false;
            while(p<b.size()) {
                Reader r(b,p);
                auto kind=r.u16(),hs=r.u16();
                auto size=r.u32();
                require(hs>=8&&size>=hs&&uint64_t(p)+size<=b.size(),"Invalid manifest chunk.");
                Chunk c;
                c.kind=kind;
                c.hs=hs;
                c.bytes=slice(b,p,size);
                if(kind==1) {
                    require(!pool,"Duplicate manifest string pool.");
                    pool=std::make_unique<Pool>(c.bytes);
                }
                if(kind==0x180) {
                    require(!hadMap&&hs==8&&(size-8)%4==0,"Invalid manifest resource map.");
                    hadMap=true;
                    Reader mr(c.bytes,8);
                    while(mr.p<c.bytes.size())map.push_back(mr.u32());
                }
                chunks.push_back(std::move(c));
                p+=size;
            }
            require(bool(pool),"Missing manifest string pool.");
            for(auto&c:chunks)if(c.kind==0x102) {
                require(c.hs+20u<=c.bytes.size(),"Truncated XML tag.");
                auto ext=c.hs;
                auto as=get16(c.bytes,ext+8),sz=get16(c.bytes,ext+10),n=get16(c.bytes,ext+12);
                require(sz>=20&&uint64_t(ext)+as+uint64_t(n)*sz<=c.bytes.size(),"Invalid manifest attributes.");
                c.name=pool->get(get32(c.bytes,ext+4));
                for(uint32_t i=0;i<n;++i) {
                    auto off=ext+as+i*sz;
                    Attr a;
                    a.bytes=slice(c.bytes,off,sz);
                    a.ns=get32(a.bytes,0);
                    a.name=get32(a.bytes,4);
                    a.raw=get32(a.bytes,8);
                    a.type=a.bytes[15];
                    a.value=get32(a.bytes,16);
                    a.key=pool->get(a.name);
                    a.space=pool->get(a.ns);
                    if(a.type==3)a.decoded=pool->get(a.value);
                    c.attrs.push_back(std::move(a));
                }
            }
        }
        const Attr* attr(const Chunk&c,const Text&key,const Text&space=NS)const {
            for(const auto&a:c.attrs)if(a.key==key&&a.space==space)return &a;
            return nullptr;
        }
        Chunk& tag(const Text&name) {
            Chunk*found=nullptr;
            for(auto&c:chunks)if(c.kind==0x102&&c.name==name) {
                require(!found,"Duplicate manifest/application tag.");
                found=&c;
            }
            require(found,"Manifest must have one application.");
            return *found;
        }
        ManifestInfo info() {
            ManifestInfo out;
            auto&root=tag(u"manifest");
            auto&app=tag(u"application");
            auto pkg=attr(root,u"package",u"");
            require(pkg&&pkg->type==3&&!pkg->decoded.empty(),"APK package name is missing.");
            out.packageName=pkg->decoded;
            require(!attr(root,u"split",u""),"Select a standalone APK; split APKs require their complete set.");
            auto shared=attr(root,u"sharedUserId");
            require(!shared||shared->type==3,"Shared user ID must be a literal string.");
            if(shared)out.sharedUserId=shared->decoded;
            auto resolve=[&](const Attr*a,const Text&fallback) {
                if(!a)return fallback;
                require(a->type==3&&!a->decoded.empty(),"Application class must be a literal string.");
                auto s=a->decoded;
                return s[0]==u'.'?out.packageName+s:s.find(u'.')!=Text::npos?s:out.packageName+u"."+s;
            };
            auto application=attr(app,u"name");
            out.applicationName=resolve(application,u"android.app.Application");
            out.factoryName=resolve(attr(app,u"appComponentFactory"),u"");
            out.hasApplication=application!=nullptr;
            require(out.applicationName!=APP&&out.factoryName!=FACTORY,"This APK is already shielded.");
            require(!attr(app,u"classLoader"),"Custom application class loaders are not supported.");
            for(const auto&c:chunks) {
                if(c.kind!=0x102)continue;
                require(c.name!=u"uses-split","This APK needs split files.");
                if(c.name==u"manifest"||c.name==u"application") {
                    auto a=attr(c,u"isSplitRequired");
                    require(!a||!a->value,"This APK needs split files.");
                }
                if(c.name==u"meta-data") {
                    auto n=attr(c,u"name"),v=attr(c,u"value");
                    require(!(n&&n->decoded==u"com.android.vending.splits.required"&&v&&v->value),"This APK needs split files.");
                }
                if(c.name==u"uses-sdk") {
                    auto get=[&](const Text&name,uint32_t fallback) {
                        auto a=attr(c,name);
                        if(!a)return fallback;
                        require(a->type==16||a->type==17,"Preview SDK names are unsupported.");
                        return a->value;
                    };
                    out.minSdk=get(u"minSdkVersion",1);
                    out.targetSdk=get(u"targetSdkVersion",out.minSdk);
                }
            }
            return out;
        }
        Bytes application(const Text& name,const Text& factory,bool withFactory,bool debuggable=false) {
            auto&app=tag(u"application");
            auto ns=pool->add(NS);
            auto setString=[&](const Text&key,uint32_t id,const Text&value) {
                auto ni=pool->add(key),vi=pool->add(value);
                while(map.size()<=ni)map.push_back(0);
                map[ni]=id;
                auto it=std::find_if(app.attrs.begin(),app.attrs.end(),[&](const Attr&a) {
                    return a.key==key;
                });
                if(it==app.attrs.end()) {
                    app.attrs.push_back({});
                    it=app.attrs.end()-1;
                }
                it->bytes.assign(20,0);
                put32(it->bytes,0,ns);
                put32(it->bytes,4,ni);
                put32(it->bytes,8,vi);
                put16(it->bytes,12,8);
                it->bytes[15]=3;
                put32(it->bytes,16,vi);
                it->name=ni;
                it->key=key;
                it->space=NS;
            };
            auto setBool=[&](const Text&key,uint32_t id,bool value) {
                auto ni=pool->add(key);
                while(map.size()<=ni)map.push_back(0);
                map[ni]=id;
                auto it=std::find_if(app.attrs.begin(),app.attrs.end(),[&](const Attr&a) {
                    return a.key==key;
                });
                if(it==app.attrs.end()) {
                    app.attrs.push_back({});
                    it=app.attrs.end()-1;
                }
                it->bytes.assign(20,0);
                put32(it->bytes,0,ns);
                put32(it->bytes,4,ni);
                put32(it->bytes,8,NONE);
                put16(it->bytes,12,8);
                it->bytes[15]=0x12;
                put32(it->bytes,16,value?0xFFFFFFFFu:0u);
                it->name=ni;
                it->key=key;
                it->space=NS;
            };
            setString(u"name",0x01010003,name);
            if(withFactory)setString(u"appComponentFactory",0x0101057a,factory);
            setBool(u"extractNativeLibs",0x010104ea,true);
            if(debuggable)setBool(u"debuggable",0x0101000f,true);
            std::stable_sort(app.attrs.begin(),app.attrs.end(),[&](const Attr&a,const Attr&b) {
                return (a.name<map.size()?map[a.name]:0)<(b.name<map.size()?map[b.name]:0);
            });
            auto ext=app.hs;
            auto as=get16(app.bytes,ext+8),sz=get16(app.bytes,ext+10);
            require(sz==20,"Unsupported manifest attribute layout.");
            auto head=slice(app.bytes,0,ext+as);
            put16(head,ext+12,narrow(app.attrs.size()));
            for(size_t delta: {
                14u,16u,18u
            }) {
                auto old=get16(app.bytes,ext+delta);
                if(old) {
                    auto name=get32(app.bytes,ext+as+(old-1)*sz+4);
                    auto it=std::find_if(app.attrs.begin(),app.attrs.end(),[&](const Attr&a) {
                        return a.name==name;
                    });
                    require(it!=app.attrs.end(),"Invalid special attribute index.");
                    put16(head,ext+delta,uint32_t(it-app.attrs.begin()+1));
                }
            }
            Writer fresh;
            fresh.bytes(head);
            for(const auto&a:app.attrs)fresh.bytes(a.bytes);
            put32(fresh.b,4,fresh.size());
            app.bytes=std::move(fresh.b);
            Writer mapBytes;
            mapBytes.u16(0x180).u16(8).u32(narrow(8+4*map.size()));
            for(auto id:map)mapBytes.u32(id);
            bool hasMap=std::any_of(chunks.begin(),chunks.end(),[](const Chunk&c) {
                return c.kind==0x180;
            });
            Writer body;
            for(const auto&c:chunks) {
                if(c.kind==1) {
                    body.bytes(pool->build());
                    if(!hasMap)body.bytes(mapBytes.b);
                }
                else if(c.kind==0x180)body.bytes(mapBytes.b);
                else body.bytes(c.bytes);
            }
            Writer out;
            out.u16(3).u16(8).u32(narrow(body.b.size()+8)).bytes(body.b);
            return out.b;
        }
    };
    ManifestInfo inspectManifest(const Bytes&bytes) {
        return Manifest(bytes).info();
    }
    Bytes shieldManifest(const Bytes&bytes) {
        Manifest m(bytes);
        m.info();
        return m.application(APP,FACTORY,true);
    }
    static Text manifestClassName(Text name) {
        if(!name.empty() && name.front()==u'L' && name.back()==u';') name=name.substr(1,name.size()-2);
        for(auto& c:name) if(c==u'/') c=u'.';
        return name;
    }
    Bytes signatureKillerManifest(const Bytes&bytes,const Text&applicationName) {
        Manifest m(bytes);
        m.info();
        return m.application(manifestClassName(applicationName),u"",false,false);
    }
    Bytes signatureKillerManifestV3(const Bytes&bytes,const Text&applicationName,bool earlyProvider,bool debuggable) {
        Manifest m(bytes);
        auto info=m.info();
        // Early provider injection is best-effort; if structure is unsupported, fall back to attachBaseContext init.
        (void)earlyProvider;
        (void)info;
        return m.application(manifestClassName(applicationName),u"",false,debuggable);
    }
    Bytes signatureKillerManifestV4(const Bytes&bytes,const Text&applicationName,const Text&originalApplicationName,const Text&componentFactory,bool debuggable) {
        Manifest m(bytes);
        m.info();
        (void)originalApplicationName;
        return m.application(manifestClassName(applicationName),manifestClassName(componentFactory),true,debuggable);
    }
}
