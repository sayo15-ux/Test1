#include "strings.hpp"
#include <chrono>
namespace dexpack {
    using namespace dex;
    static const Text STR=u"Ljava/lang/String;",ARRAY=u"[Ljava/lang/String;";
    StringReport& StringReport::operator+=(const StringReport&r) {
        classes+=r.classes;
        literals+=r.literals;
        staticFields+=r.staticFields;
        uniqueStrings+=r.uniqueStrings;
        classTables+=r.classTables;
        methodsReframed+=r.methodsReframed;
        highRegisterSites+=r.highRegisterSites;
        bridges+=r.bridges;
        interfacesPreserved+=r.interfacesPreserved;
        return *this;
    }
    StringContext::StringContext(std::string t):token(std::move(t)),millis([] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }) {}

    void StringContext::prepare(int requested,const std::set<Text>&occupied) {
        require(requested==1||requested==2,"Choose String Encryption V1 or V2.");
        if(version) {
            require(version==requested,"String context belongs to another encryption version.");
            require(!occupied.count(owner),"String helper class collision.");
            return;
        }
        auto model=read(requested==1?payload::v1():payload::v2());
        require(model.classes.size()==1,"Invalid string helper template.");
        const auto&c=model.classes[0];
        templateOwner=c.type;
        owner=templateOwner;
        uint32_t suffix=0;
        while(occupied.count(owner)) {
            owner=templateOwner.substr(0,templateOwner.size()-1)+u"$"+utf16(token);
            if(suffix)owner+=u"$"+utf16(std::to_string(suffix));
            owner+=u";";
            ++suffix;
        }
        const std::vector<Text>params(requested==1?2:1,STR);
        for(const auto&m:c.direct) {
            if(m->flags!=9||m->ref->proto->type!=STR||m->ref->proto->params!=params||!m->code)continue;
            bool marker=false,decode=false;
            for(const auto&i:m->code->instructions)if(i.ref) {
                marker|=i.ref->kind==Kind::String&&i.ref->text==u"Fallen-";
                decode|=i.ref->kind==Kind::Method&&i.ref->owner==templateOwner&&i.ref->text==u"decode";
            }
            if(marker&&decode) {
                require(!decoder,"Ambiguous string decoder template.");
                decoder=method(owner,m->ref->text,STR,params);
            }
        }
        require(bool(decoder),"Missing reference string decoder.");
        version=requested;
    }

    static bool eligible(const Text&s) {
        return !s.empty()&&s.compare(0,7,u"Fallen-")!=0&&validText(s);
    }
    static std::vector<std::shared_ptr<Method>> methods(const Class&c) {
        auto a=c.direct;
        a.insert(a.end(),c.virtuals.begin(),c.virtuals.end());
        return a;
    }
    static void editable(const std::shared_ptr<Method>&m) {
        require(bool(m->code),"Missing method code.");
        m->code=std::make_shared<Code>(*m->code);
    }
    static Instruction move(uint32_t dst,uint32_t src,const Text&type) {
        require(dst<=65535&&src<=65535,"Register overflow.");
        require(!type.empty(),"Empty parameter type.");
        uint16_t op=type==u"J"||type==u"D"?4:type[0]==u'L'||type[0]==u'['?7:1;
        return dst<=255?raw( {
            uint16_t((op+1)|(dst<<8)),uint16_t(src)
        }):raw( {
            uint16_t(op+2),uint16_t(dst),uint16_t(src)
        });
    }
    struct Frame {
        uint16_t base;
        std::vector<Instruction>prefix;
    };
    static Frame reframe(const std::shared_ptr<Method>&m) {
        auto&c=*m->code;
        auto old=c.registers;
        std::vector<Text>types;
        if(!(m->flags&8))types.push_back(m->ref->owner);
        types.insert(types.end(),m->ref->proto->params.begin(),m->ref->proto->params.end());
        uint32_t words=0;
        for(const auto&t:types)words+=t==u"J"||t==u"D"?2:1;
        require(words==c.ins,"Invalid incoming parameter frame in "+utf8(m->ref->text));
        require(old+words+3<=65535,"DEX register frame exceeds its format.");
        Frame frame {
            uint16_t(old),{}
        };
        auto dest=old-words,source=old+3;
        for(const auto&t:types) {
            frame.prefix.push_back(move(dest,source,t));
            auto width=t==u"J"||t==u"D"?2u:1u;
            dest+=width;
            source+=width;
        }
        c.registers=old+words+3;
        return frame;
    }
    static void checkSite(const std::vector<Instruction>&seq,uint32_t original,uint16_t dest) {
        require(!seq.empty()&&dest<original&&seq.back().op==12&&(seq.back().units[0]>>8)==dest,"Invalid string-result register.");
        for(size_t i=0;i+1<seq.size();++i) {
            auto op=seq[i].op;
            auto a=seq[i].units[0]>>8;
            bool safe=(op==26||op==27||op==19||op==20||op==0x62||op==12)?uint32_t(a)>=original:(op==0x77||op==0x74)?(!a||seq[i].units[2]>=original):op==0x71&&(seq[i].units[0]>>12)==0;
            require(safe,"String injection would overwrite an exception-handler register.");
        }
    }
    static void append(std::vector<Instruction>&dst,const std::vector<Instruction>&src) {
        dst.insert(dst.end(),src.begin(),src.end());
    }
    static std::shared_ptr<Method> initializer(Class&c,uint32_t registers) {
        for(const auto&m:c.direct)if(m->ref->text==u"<clinit>")return m;
        auto m=newMethod(method(c.type,u"<clinit>",u"V"),0x10008,newCode( {
            raw( {
                14
            })
        },registers));
        c.direct.push_back(m);
        return m;
    }
    static bool moveStatic(Class&c) {
        std::vector<Field*>fields;
        for(auto&f:c.staticFields)if(f.value&&f.value->ref&&f.value->ref->kind==Kind::String&&validText(f.value->ref->text))fields.push_back(&f);
        if(fields.empty()||(c.flags&0x200))return false;
        auto init=initializer(c,1);
        editable(init);
        init->code->registers=std::max(1u,init->code->registers);
        std::vector<Instruction>prefix;
        for(auto*f:fields) {
            auto literal=string(0,f->value->ref->text);
            literal.movedStatic=true;
            prefix.push_back(literal);
            prefix.push_back(raw( {
                0x69,0
            },f->ref));
            f->value=Value{};
        }
        append(prefix,init->code->instructions);
        init->code->instructions=std::move(prefix);
        return true;
    }
    static Text fresh(const Class&c,const Text&base,bool isField) {
        std::set<Text>used;
        if(isField) {
            for(auto*g: {
                &c.staticFields,&c.instanceFields
            })for(const auto&f:*g)used.insert(f.ref->text);
        }
        else for(const auto&m:methods(c))used.insert(m->ref->text);
        auto name=base;
        uint32_t n=0;
        while(used.count(name))name=base+u"$"+utf16(std::to_string(++n));
        return name;
    }
    static Ref arrayGet() {
        return method(u"Ljava/lang/reflect/Array;",u"get",u"Ljava/lang/Object;", {
            u"Ljava/lang/Object;",u"I"
        });
    }
    static Ref objectString() {
        return method(u"Ljava/lang/Object;",u"toString",STR);
    }
    static std::vector<Instruction> lookup(const Ref&f,uint32_t index,uint16_t base,uint16_t dest) {
        return {
            raw( {
                uint16_t(0x62|(base<<8)),0
            },f),constant(uint16_t(base+1),int32_t(index)),invoke(arrayGet(),base,2),raw( {
                uint16_t(12|((base+2)<<8))
            }),raw( {
                0x0174,0,uint16_t(base+2)
            },objectString()),raw( {
                uint16_t(12|(dest<<8))
            })
        };
    }
    static std::vector<Instruction> v2Initializer(const Ref&f,const std::vector<Text>&strings,StringContext&ctx) {
        auto decoder=ctx.decoder;
        auto n=narrow(strings.size());
        std::vector<Instruction>code {
            constant(2,int32_t(n)),raw( {
                0x2323,0
            },textRef(Kind::Type,ARRAY))
        };
        for(uint32_t i=0;i<n;++i) {
            auto found=ctx.v2.find(strings[i]);
            if(found==ctx.v2.end())found=ctx.v2.emplace(strings[i],encryptString(strings[i],u"Fallen")).first;
            append(code, {
                string(1,found->second),constant(2,int32_t(i)),raw( {
                    0x014d,0x0203
                })
            });
        }
        append(code, {
            constant(2,int32_t(n)),raw( {
                0x2023,0
            },textRef(Kind::Type,ARRAY))
        });
        for(uint32_t i=0;i<n;++i)append(code, {
            constant(2,int32_t(i)),raw( {
                0x0146,0x0203
            }),invoke(decoder,1),raw( {
                0x010c
            }),constant(2,int32_t(i)),raw( {
                0x014d,0x0200
            })
        });
        code.push_back(raw( {
            0x69,0
        },f));
        return code;
    }
    StringResult transformStrings(const Bytes&input,int version,const std::set<Text>&selected,StringContext&ctx,const Progress&progress) {
        require(version==1||version==2,"Choose String Encryption V1 or V2.");
        ctx.prepare(version);
        auto model=read(input);
        StringResult result;
        auto&report=result.report;
        auto decoder=ctx.decoder;
        for(size_t n=0;n<model.classes.size();++n) {
            auto&c=model.classes[n];
            if(!selected.count(c.type))continue;
            require(c.type!=ctx.owner,"Generated helper name collision.");
            if(version==2&&(c.flags&0x200)) {
                ++report.interfacesPreserved;
                continue;
            }
            if(moveStatic(c))result.changed=true;
            if(version==1) {
                std::set<Text>unique;
                auto before=report.literals+report.staticFields;
                for(const auto&m:methods(c)) {
                    if(!m->code)continue;
                    bool has=false;
                    for(const auto&i:m->code->instructions)if((i.op==26||i.op==27)&&eligible(i.ref->text)) {
                        has=true;
                        break;
                    }
                    if(!has)continue;
                    editable(m);
                    auto old=m->code->registers;
                    std::optional<Frame>frame;
                    if(old<=254) {
                        frame=reframe(m);
                        ++report.methodsReframed;
                    }
                    std::vector<Instruction>changed=frame?frame->prefix:std::vector<Instruction>{};
                    for(const auto&i:m->code->instructions) {
                        if((i.op!=26&&i.op!=27)||!eligible(i.ref->text)) {
                            changed.push_back(i);
                            continue;
                        }
                        const auto&text=i.ref->text;
                        auto password=utf16("Fallen-"+hex(md5(ascii(utf8(c.type)+std::to_string(ctx.millis())))).substr(8,16));
                        auto cache=std::make_pair(password,text);
                        auto it=ctx.v1.find(cache);
                        if(it==ctx.v1.end())it=ctx.v1.emplace(cache,encryptString(text,password)).first;
                        const auto&cipher=it->second;
                        auto dest=uint16_t(i.units[0]>>8);
                        std::vector<Instruction>seq;
                        if(frame) {
                            seq= {
                                string(frame->base,cipher),string(uint16_t(frame->base+1),password),invoke(decoder,frame->base,2),raw( {
                                    uint16_t(12|(dest<<8))
                                })
                            };
                            m->code->outs=std::max(2u,m->code->outs);
                        }
                        else {
                            auto bridge=ctx.bridges.find(cache);
                            if(bridge==ctx.bridges.end()) {
                                auto ref=method(ctx.owner,u"v1$"+utf16(std::to_string(ctx.bridges.size())),STR);
                                bridge=ctx.bridges.emplace(cache,StringContext::Bridge {
                                    ref,cipher,password
                                }).first;
                                ++report.bridges;
                            }
                            seq= {
                                raw( {
                                    0x71,0,0
                                },bridge->second.ref),raw( {
                                    uint16_t(12|(dest<<8))
                                })
                            };
                            ++report.highRegisterSites;
                        }
                        checkSite(seq,old,dest);
                        seq[0].oldPc=i.oldPc;
                        append(changed,seq);
                        if(i.movedStatic)++report.staticFields;
                        else ++report.literals;
                        unique.insert(text);
                    }
                    m->code->instructions=std::move(changed);
                    result.changed=true;
                }
                if(report.literals+report.staticFields>before)++report.classes;
                report.uniqueStrings+=unique.size();
            }
            else {
                std::map<Text,uint32_t>unique;
                std::vector<Text>ordered;
                for(const auto&m:methods(c))if(m->code)for(const auto&i:m->code->instructions)if((i.op==26||i.op==27)&&eligible(i.ref->text)&&!unique.count(i.ref->text)) {
                    unique[i.ref->text]=narrow(ordered.size());
                    ordered.push_back(i.ref->text);
                }
                if(unique.empty())continue;
                auto f=field(c.type,fresh(c,u"$fallen$"+utf16(ctx.token),true),ARRAY);
                c.staticFields.push_back( {
                    f,10,{}
                });
                auto init=initializer(c,4);
                editable(init);
                init->code->registers=std::max(4u,init->code->registers);
                init->code->outs=std::max(1u,init->code->outs);
                std::map<uint32_t,Ref>bridges;
                for(const auto&m:methods(c)) {
                    if(!m->code)continue;
                    bool has=false;
                    for(const auto&i:m->code->instructions)if((i.op==26||i.op==27)&&unique.count(i.ref->text)) {
                        has=true;
                        break;
                    }
                    if(!has)continue;
                    editable(m);
                    auto old=m->code->registers;
                    std::optional<Frame>frame;
                    if(old<=253) {
                        frame=reframe(m);
                        ++report.methodsReframed;
                    }
                    std::vector<Instruction>changed=frame?frame->prefix:std::vector<Instruction>{};
                    for(const auto&i:m->code->instructions) {
                        if((i.op!=26&&i.op!=27)||!unique.count(i.ref->text)) {
                            changed.push_back(i);
                            continue;
                        }
                        auto dest=uint16_t(i.units[0]>>8);
                        auto index=unique[i.ref->text];
                        std::vector<Instruction>seq;
                        if(frame) {
                            seq=lookup(f,index,frame->base,dest);
                            m->code->outs=std::max(2u,m->code->outs);
                        }
                        else {
                            auto it=bridges.find(index);
                            if(it==bridges.end()) {
                                auto ref=method(c.type,fresh(c,u"$fallen$get$"+utf16(std::to_string(index)),false),STR);
                                it=bridges.emplace(index,ref).first;
                                auto code=lookup(f,index,0,0);
                                code.push_back(raw( {
                                    17
                                }));
                                c.direct.push_back(newMethod(ref,0x100a,newCode(code,3,0,2)));
                                ++report.bridges;
                            }
                            seq= {
                                raw( {
                                    0x71,0,0
                                },it->second),raw( {
                                    uint16_t(12|(dest<<8))
                                })
                            };
                            ++report.highRegisterSites;
                        }
                        checkSite(seq,old,dest);
                        seq[0].oldPc=i.oldPc;
                        append(changed,seq);
                        if(i.movedStatic)++report.staticFields;
                        else ++report.literals;
                    }
                    m->code->instructions=std::move(changed);
                }
                auto prefix=v2Initializer(f,ordered,ctx);
                append(prefix,init->code->instructions);
                init->code->instructions=std::move(prefix);
                ++report.classes;
                ++report.classTables;
                report.uniqueStrings+=unique.size();
                result.changed=true;
            }
            if(progress&&n%16==0)progress("Building DEX",int((n+1)*100/model.classes.size()));
        }
        result.bytes=result.changed?write(model):input;
        validateDex(result.bytes);
        return result;
    }
    Model stringHelper(int version,StringContext&ctx) {
        ctx.prepare(version);
        auto model=read(version==1?payload::v1():payload::v2());
        if(ctx.owner!=ctx.templateOwner)rename(model,ctx.templateOwner,ctx.owner);
        require(model.classes.size()==1,"Invalid string helper template.");
        if(version==1)for(const auto&p:ctx.bridges) {
            const auto&b=p.second;
            model.classes[0].direct.push_back(newMethod(b.ref,9,newCode( {
                string(0,b.cipher),string(1,b.password),invoke(ctx.decoder,0,2),raw( {
                    12
                }),raw( {
                    17
                })
            },2,0,2)));
        }
        return model;
    }
    Bytes stringHelperDex(int version,StringContext&ctx) {
        ctx.prepare(version);
        if(ctx.owner==ctx.templateOwner&&ctx.bridges.empty())return version==1?payload::v1():payload::v2();
        return write(stringHelper(version,ctx));
    }
}
