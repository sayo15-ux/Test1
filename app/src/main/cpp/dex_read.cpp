#include "dex.hpp"
namespace dexpack::dex {
    Ref textRef(Kind k,const Text& s) {
        auto r=std::make_shared<Symbol>();
        r->kind=k;
        r->text=s;
        return r;
    }
    Ref prototype(const Text& result,const std::vector<Text>& params) {
        auto r=textRef(Kind::Proto,{});
        r->type=result;
        r->params=params;
        return r;
    }
    Ref method(const Text& owner,const Text& name,const Text& result,const std::vector<Text>& params) {
        auto r=textRef(Kind::Method,name);
        r->owner=owner;
        r->proto=prototype(result,params);
        return r;
    }
    Ref field(const Text& owner,const Text& name,const Text& type) {
        auto r=textRef(Kind::Field,name);
        r->owner=owner;
        r->type=type;
        return r;
    }
    Text key(const Ref& r) {
        require(bool(r),"Missing DEX reference.");
        switch(r->kind) {
            case Kind::Proto: {
                Text s=r->type+u"(";
                for(const auto& p:r->params)s+=p;
                return s+u")";
            }
            case Kind::Field:return r->owner+u"->"+r->text+u":"+r->type;
            case Kind::Method:return r->owner+u"->"+r->text+key(r->proto);
            case Kind::Handle:case Kind::Callsite:return utf16(std::to_string(r->index));
            default:return r->text;
        }
    }
    Text shorty(const Ref& p) {
        auto shortType=[](const Text& t) {
            require(!t.empty(),"Empty DEX type.");
            return t[0]==u'L'||t[0]==u'['?u'L':t[0];
        };
        Text s(1,shortType(p->type));
        for(const auto& t:p->params)s+=shortType(t);
        return s;
    }
    Instruction raw(std::initializer_list<uint16_t> u,Ref ref) {
        Instruction i;
        i.units=u;
        require(!i.units.empty(),"Empty instruction.");
        i.op=uint8_t(i.units[0]);
        i.ref=std::move(ref);
        return i;
    }
    Instruction constant(uint16_t reg,int32_t value) {
        require(reg<=255,"Constant register exceeds 8 bits.");
        return value>=-32768&&value<=32767?raw( {
            uint16_t(0x13|(reg<<8)),uint16_t(value)
        }):raw( {
            uint16_t(0x14|(reg<<8)),uint16_t(value),uint16_t(uint32_t(value)>>16)
        });
    }
    Instruction string(uint16_t reg,const Text& text) {
        require(reg<=255,"String register exceeds 8 bits.");
        return raw( {
            uint16_t(0x1b|(reg<<8)),0,0
        },textRef(Kind::String,text));
    }
    Instruction invoke(const Ref& ref,uint16_t base,uint8_t count) {
        return raw( {
            uint16_t(0x77|(uint16_t(count)<<8)),0,base
        },ref);
    }
    std::shared_ptr<Code> newCode(std::vector<Instruction> instructions,uint32_t registers,uint32_t ins,uint32_t outs) {
        auto c=std::make_shared<Code>();
        c->instructions=std::move(instructions);
        c->registers=registers;
        c->ins=ins;
        c->outs=outs;
        return c;
    }
    std::shared_ptr<Method> newMethod(const Ref& ref,uint32_t flags,std::shared_ptr<Code> code) {
        return std::make_shared<Method>(Method {
            ref,flags,std::move(code)
        });
    }
    static const auto WIDTH=[] {
        std::array<uint8_t,256>w{};
        auto add=[&](int n,std::initializer_list<int>a) {
            for(auto op:a)w[op]=uint8_t(n);
        };
        add(1, {
            0,1,4,7,10,11,12,13,14,15,16,17,18,29,30,33,39,40
        });
        add(2, {
            2,5,8,19,21,22,25,26,28,31,32,34,35,41
        });
        add(3, {
            3,6,9,20,23,27,36,37,38,42,43,44,252,253
        });
        add(4, {
            250,251
        });
        add(5, {
            24
        });
        for(auto r:std::vector<std::array<int,3>> {
            {
                0x2d,0x3d,2
            }, {
                0x44,0x6d,2
            }, {
                0x6e,0x72,3
            }, {
                0x74,0x78,3
            }, {
                0x7b,0x8f,1
            }, {
                0x90,0xaf,2
            }, {
                0xb0,0xcf,1
            }, {
                0xd0,0xe2,2
            }, {
                0xfe,0xff,2
            }
        })for(int op=r[0];op<=r[1];++op)w[op]=uint8_t(r[2]);
        return w;
    }
    ();
    static Kind symbolKind(uint8_t op) {
        if(op==26||op==27)return Kind::String;
        if(op==28||op==31||op==32||op==34||op==35||op==36||op==37)return Kind::Type;
        if(op>=0x52&&op<=0x6d)return Kind::Field;
        if((op>=0x6e&&op<=0x72)||(op>=0x74&&op<=0x78)||op==250||op==251)return Kind::Method;
        if(op==252||op==253)return Kind::Callsite;
        if(op==254)return Kind::Handle;
        if(op==255)return Kind::Proto;
        return Kind::None;
    }
    struct Parser {
        const Bytes& b;
        Model model;
        std::array<std::vector<Ref>,8> refs;
        struct Table {
            uint32_t n,off;
        };
        std::array<Table,6> tables{};
        std::map<uint16_t,Table> maps;
        std::map<uint32_t,std::shared_ptr<Code>> codeMemo;
        std::map<uint32_t,std::shared_ptr<Debug>> debugMemo;
        std::map<uint32_t,Ann> annMemo;
        std::map<uint32_t,AnnSet> setMemo;
        std::map<uint32_t,AnnParams> paramsMemo;
        std::map<uint32_t,std::shared_ptr<Directory>> directoryMemo;
        std::set<uint32_t> activeOffsets;
        bool skipDebug=false;
        bool skipAnnotations=false;
        explicit Parser(const Bytes& input):b(input) {
            validateDex(b);
            model.version=std::string(b.begin()+4,b.begin()+7);
            Reader h(b,44);
            require(h.u32()==0&&h.u32()==0,"Linked DEX files are unsupported.");
            auto mapOff=h.u32();
            const uint32_t widths[] {
                4,4,12,8,8,32
            };
            for(size_t i=0;i<6;++i) {
                auto n=h.u32(),off=h.u32();
                tables[i]= {
                    n,off
                };
                require(n?off>=112&&off%4==0&&uint64_t(off)+uint64_t(n)*widths[i]<=b.size():off==0,"Invalid DEX table bounds.");
            }
            auto size=h.u32(),off=h.u32();
            require(uint64_t(size)+off==b.size(),"Invalid DEX data bounds.");
            Reader mr(b,mapOff);
            auto count=mr.count(mr.u32());
            const std::set<uint16_t>known {
                0,1,2,3,4,5,6,7,8,0x1000,0x1001,0x1002,0x1003,0x2000,0x2001,0x2002,0x2003,0x2004,0x2005,0x2006
            };
            for(uint32_t i=0;i<count;++i) {
                auto t=mr.u16();
                require(mr.u16()==0,"Invalid DEX map padding.");
                auto n=mr.u32(),p=mr.u32();
                require(known.count(t)&&!maps.count(t)&&p<b.size(),"Unsupported or invalid DEX map.");
                maps[t]= {
                    n,p
                };
            }
            Reader sr(b,tables[0].off);
            for(uint32_t i=0;i<tables[0].n;++i) {
                Reader r(b,sr.u32());
                refs[size_t(Kind::String)].push_back(textRef(Kind::String,mutfRead(r)));
            }
            Reader tr(b,tables[1].off);
            for(uint32_t i=0;i<tables[1].n;++i)refs[size_t(Kind::Type)].push_back(textRef(Kind::Type,at(Kind::String,tr.u32())->text));
        }
        Ref at(Kind k,uint32_t index)const {
            const auto&a=refs[size_t(k)];
            require(index<a.size(),"Invalid DEX reference index.");
            return a[index];
        }
        std::vector<Text> list(uint32_t off) {
            if(!off)return {};
            Reader r(b,off);
            auto n=r.count(r.u32());
            r.need(size_t(n)*2);
            std::vector<Text>a;
            for(uint32_t i=0;i<n;++i)a.push_back(at(Kind::Type,r.u16())->text);
            return a;
        }
        std::optional<Text> opt(Reader&r,Kind k) {
            auto n=r.u();
            return n?std::optional<Text>(at(k,n-1)->text):std::nullopt;
        }
        Ann annotation(Reader&r,unsigned depth) {
            require(depth<128,"DEX annotation nesting too deep.");
            auto a=std::make_shared<Annotation>();
            a->type=at(Kind::Type,r.u())->text;
            auto n=r.count(r.u());
            for(uint32_t i=0;i<n;++i) {
                auto name=at(Kind::String,r.u())->text;
                auto v=value(r,depth+1);
                a->items.emplace_back(std::move(name),std::move(v));
            }
            return a;
        }
        std::vector<Value> array(Reader&r,unsigned depth) {
            require(depth<128,"DEX value nesting too deep.");
            auto n=r.count(r.u());
            std::vector<Value>a;
            for(uint32_t i=0;i<n;++i)a.push_back(value(r,depth+1));
            return a;
        }
        Value value(Reader&r,unsigned depth=0) {
            Value v;
            auto tag=r.u8();
            v.type=tag&31;
            v.arg=tag>>5;
            if(v.type==28) {
                require(v.arg==0,"Invalid DEX array.");
                v.items=array(r,depth);
            }
            else if(v.type==29) {
                require(v.arg==0,"Invalid DEX annotation.");
                v.annotation=annotation(r,depth);
            }
            else if(v.type==30||v.type==31) {
                require(v.type==30?v.arg==0:v.arg<=1,"Invalid DEX value.");
            }
            else {
                auto n=uint32_t(v.arg)+1;
                v.raw=r.take(n);
                Kind kind=Kind::None;
                switch(v.type) {
                    case 21:kind=Kind::Proto;
                    break;
                    case 22:kind=Kind::Handle;
                    break;
                    case 23:kind=Kind::String;
                    break;
                    case 24:kind=Kind::Type;
                    break;
                    case 25:case 27:kind=Kind::Field;
                    break;
                    case 26:kind=Kind::Method;
                    break;
                    default:break;
                }
                if(kind!=Kind::None) {
                    require(n<=4,"Invalid encoded DEX reference.");
                    uint32_t index=0;
                    for(uint32_t i=0;i<n;++i)index|=uint32_t(v.raw[i])<<(8*i);
                    v.ref=at(kind,index);
                    v.raw.clear();
                }
                else {
                    std::map<uint8_t,unsigned>max {
                        {
                            0,1
                        }, {
                            2,2
                        }, {
                            3,2
                        }, {
                            4,4
                        }, {
                            6,8
                        }, {
                            16,4
                        }, {
                            17,8
                        }
                    };
                    require(max[v.type]>=n,"Unsupported encoded DEX value.");
                }
            }
            return v;
        }
        Ann annotationItem(uint32_t off) {
            if(!off)return {};
            if(annMemo.count(off))return annMemo[off];
            Reader r(b,off);
            auto visibility=r.u8();
            require(visibility<=2,"Invalid annotation visibility.");
            auto a=annotation(r,0);
            a->visibility=visibility;
            return annMemo[off]=a;
        }
        AnnSet annotationSet(uint32_t off) {
            if(!off)return {};
            if(setMemo.count(off))return setMemo[off];
            Reader r(b,off);
            auto n=r.count(r.u32());
            auto a=std::make_shared<std::vector<Ann>>();
            for(uint32_t i=0;i<n;++i) {
                auto item=annotationItem(r.u32());
                require(bool(item),"Null annotation.");
                a->push_back(item);
            }
            return setMemo[off]=a;
        }
        AnnParams paramAnnotations(uint32_t off) {
            if(!off)return {};
            if(paramsMemo.count(off))return paramsMemo[off];
            Reader r(b,off);
            auto n=r.count(r.u32());
            auto a=std::make_shared<std::vector<AnnSet>>();
            for(uint32_t i=0;i<n;++i)a->push_back(annotationSet(r.u32()));
            return paramsMemo[off]=a;
        }
        std::shared_ptr<Directory> directory(uint32_t off) {
            if(!off)return {};
            if(directoryMemo.count(off))return directoryMemo[off];
            Reader r(b,off);
            auto a=std::make_shared<Directory>();
            a->cls=annotationSet(r.u32());
            auto nf=r.count(r.u32()),nm=r.count(r.u32()),np=r.count(r.u32());
            for(uint32_t i=0;i<nf;++i) {
                auto ref=at(Kind::Field,r.u32());
                auto set=annotationSet(r.u32());
                a->fields.emplace_back(ref,set);
            }
            for(uint32_t i=0;i<nm;++i) {
                auto ref=at(Kind::Method,r.u32());
                auto set=annotationSet(r.u32());
                a->methods.emplace_back(ref,set);
            }
            for(uint32_t i=0;i<np;++i) {
                auto ref=at(Kind::Method,r.u32());
                auto sets=paramAnnotations(r.u32());
                a->params.emplace_back(ref,sets);
            }
            return directoryMemo[off]=a;
        }
        std::shared_ptr<Debug> debug(uint32_t off) {
            if(!off)return {};
            if(debugMemo.count(off))return debugMemo[off];
            try {
                Reader r(b,off);
                auto d=std::make_shared<Debug>();
                d->line=r.u();
                auto n=r.count(r.u());
                for(uint32_t i=0;i<n;++i)d->params.push_back(opt(r,Kind::String));
                uint32_t pc=0;
                for(;;) {
                    auto op=r.u8();
                    if(!op)break;
                    DebugEvent e;
                    e.op=op;
                    e.pc=pc;
                    if(op==1) {
                        uint64_t next=uint64_t(pc)+r.u();
                        if(next>NONE) return debugMemo[off]={};
                        pc=uint32_t(next);
                        e.pc=pc;
                    }
                    else if(op==2)e.line=r.s();
                    else if(op==3||op==4) {
                        e.reg=r.u();
                        e.name=opt(r,Kind::String);
                        e.type=opt(r,Kind::Type);
                        if(op==4)e.sig=opt(r,Kind::String);
                    }
                    else if(op==5||op==6)e.reg=r.u();
                    else if(op==9)e.file=opt(r,Kind::String);
                    else if(op>=10) {
                        pc+=(op-10)/15;
                        e.pc=pc;
                        e.line=-4+(op-10)%15;
                    }
                    else if(op!=7&&op!=8) return debugMemo[off]={};
                    d->events.push_back(e);
                }
                return debugMemo[off]=d;
            } catch(...) {
                return debugMemo[off]={};
            }
        }
        std::shared_ptr<Code> code(uint32_t off) {
            if(!off)return {};
            if(codeMemo.count(off))return codeMemo[off];
            Reader r(b,off);
            auto c=std::make_shared<Code>();
            c->registers=r.u16();
            c->ins=r.u16();
            c->outs=r.u16();
            auto triesCount=r.u16();
            auto debugOff=r.u32(),count=r.u32();
            c->oldSize=count;
            require(c->ins<=c->registers,"Invalid DEX register frame.");
            r.need(size_t(count)*2);
            std::vector<uint16_t>units;
            units.reserve(count);
            for(uint32_t i=0;i<count;++i)units.push_back(r.u16());
            auto u=[&](uint64_t p) {
                require(p<units.size(),"Truncated DEX instruction.");
                return units[size_t(p)];
            };
            auto signed32=[&](uint64_t p) {
                return int32_t(uint32_t(u(p))|(uint32_t(u(p+1))<<16));
            };
            for(uint32_t pc=0;pc<count;) {
                auto word=u(pc);
                Instruction i;
                i.oldPc=pc;
                i.op=uint8_t(word);
                uint64_t width=WIDTH[i.op];
                if(!i.op&&word) {
                    i.payload=word;
                    if(word==256)width=4+2*uint64_t(u(pc+1));
                    else if(word==512)width=2+4*uint64_t(u(pc+1));
                    else if(word==768)width=4+(uint64_t(u(pc+1))*(uint32_t(u(pc+2))+(uint32_t(u(pc+3))<<16))+1)/2;
                    else throw std::runtime_error("Unknown DEX payload.");
                    require(pc%2==0,"Unaligned DEX payload.");
                }
                require(width&&uint64_t(pc)+width<=count,"Unsupported or truncated DEX opcode.");
                i.units.assign(units.begin()+pc,units.begin()+pc+size_t(width));
                auto kind=symbolKind(i.op);
                if(kind!=Kind::None) {
                    auto index=i.op==27?uint32_t(u(pc+1))+(uint32_t(u(pc+2))<<16):u(pc+1);
                    i.ref=at(kind,index);
                    if(i.op==250||i.op==251)i.proto=at(Kind::Proto,u(pc+3));
                }
                if(i.op==40)i.target=int64_t(pc)+int8_t(word>>8);
                else if(i.op==41||(i.op>=0x32&&i.op<=0x3d))i.target=int64_t(pc)+int16_t(u(pc+1));
                else if(i.op==42||i.op==38||i.op==43||i.op==44)i.target=int64_t(pc)+signed32(pc+1);
                c->instructions.push_back(std::move(i));
                pc+=uint32_t(width);
            }
            std::map<uint32_t,size_t>starts;
            for(size_t i=0;i<c->instructions.size();++i)starts[uint32_t(c->instructions[i].oldPc)]=i;
            for(auto&i:c->instructions) {
                bool branch=i.op==40||i.op==41||i.op==42||i.op==38||i.op==43||i.op==44||(i.op>=0x32&&i.op<=0x3d);
                if(!branch)continue;
                if(!(i.target>=0&&i.target<NONE&&starts.count(uint32_t(i.target)))) {
                    std::string detail="Invalid DEX branch target: op="+std::to_string(i.op)+" oldPc="+std::to_string(i.oldPc)+" target="+std::to_string(i.target)+" count="+std::to_string(c->instructions.size());
                    for(size_t di=0;di<c->instructions.size();++di){ auto& ins=c->instructions[di]; detail+=" ["+std::to_string(di)+"]pc="+std::to_string(ins.oldPc)+" op="+std::to_string(ins.op)+" w="+std::to_string(ins.units.size()); }
                    throw std::runtime_error(detail);
                }
                const auto&p=c->instructions[starts[uint32_t(i.target)]];
                if(i.op==43||i.op==44) {
                    require(p.payload==(i.op==43?256:512),"Invalid switch payload.");
                    auto n=p.units[1];
                    size_t base=p.payload==256?4:2+2*n;
                    for(size_t j=0;j<n;++j) {
                        int64_t target=i.oldPc+int32_t(uint32_t(p.units[base+2*j])|(uint32_t(p.units[base+2*j+1])<<16));
                        require(target>=0&&target<NONE&&starts.count(uint32_t(target)),"Invalid switch case.");
                        i.cases.push_back(uint32_t(target));
                    }
                }
                if(i.op==38)require(p.payload==768,"Invalid array payload.");
            }
            if(triesCount) {
                if(count%2)require(r.u16()==0,"Invalid try padding.");
                struct RawTry {
                    uint32_t start;
                    uint16_t length,handler;
                };
                std::vector<RawTry>rawTries;
                for(uint32_t i=0;i<triesCount;++i) {
                    auto start=r.u32();
                    auto length=r.u16(),handler=r.u16();
                    rawTries.push_back( {
                        start,length,handler
                    });
                }
                auto base=r.p;
                auto n=r.count(r.u());
                std::map<size_t,std::shared_ptr<Handler>>handlers;
                for(uint32_t j=0;j<n;++j) {
                    auto offset=r.p-base;
                    int32_t s=r.s();
                    require(s!=std::numeric_limits<int32_t>::min(),"Invalid catch count.");
                    auto h=std::make_shared<Handler>();
                    for(int64_t k=0;k<std::abs(int64_t(s));++k) {
                        auto type=at(Kind::Type,r.u())->text;
                        auto pc=r.u();
                        h->types.emplace_back(type,pc);
                    }
                    if(s<=0)h->catchAll=r.u();
                    handlers[offset]=h;
                }
                for(const auto&t:rawTries) {
                    require(starts.count(t.start)&&t.length&&uint64_t(t.start)+t.length<=count&&(starts.count(t.start+t.length)||t.start+t.length==count)&&handlers.count(t.handler),"Invalid DEX exception table.");
                    auto h=handlers[t.handler];
                    auto check=[&](uint32_t pc) {
                        require(starts.count(pc)&&!c->instructions[starts[pc]].payload,"Invalid exception handler.");
                    };
                    for(const auto&p:h->types)check(p.second);
                    if(h->catchAll)check(*h->catchAll);
                    c->tries.push_back( {
                        t.start,t.length,h
                    });
                }
            }
            c->debug=skipDebug?std::shared_ptr<Debug>{}:debug(debugOff);
            return codeMemo[off]=c;
        }
        Model parse() {
            Reader pr(b,tables[2].off);
            for(uint32_t i=0;i<tables[2].n;++i) {
                auto s=at(Kind::String,pr.u32())->text;
                auto result=at(Kind::Type,pr.u32())->text;
                auto params=list(pr.u32());
                auto p=prototype(result,params);
                require(shorty(p)==s,"Invalid DEX prototype.");
                refs[size_t(Kind::Proto)].push_back(p);
            }
            Reader fr(b,tables[3].off);
            for(uint32_t i=0;i<tables[3].n;++i) {
                auto owner=at(Kind::Type,fr.u16())->text,type=at(Kind::Type,fr.u16())->text,name=at(Kind::String,fr.u32())->text;
                refs[size_t(Kind::Field)].push_back(field(owner,name,type));
            }
            Reader mr(b,tables[4].off);
            for(uint32_t i=0;i<tables[4].n;++i) {
                auto owner=at(Kind::Type,mr.u16())->text;
                auto proto=at(Kind::Proto,mr.u16());
                auto name=at(Kind::String,mr.u32())->text;
                auto ref=textRef(Kind::Method,name);
                ref->owner=owner;
                ref->proto=proto;
                refs[size_t(Kind::Method)].push_back(ref);
            }
            if(maps.count(8)) {
                auto t=maps[8];
                Reader r(b,t.off);
                r.need(size_t(t.n)*8);
                for(uint32_t i=0;i<t.n;++i) {
                    auto kind=r.u16();
                    require(kind<=8&&r.u16()==0,"Invalid method handle.");
                    auto ref=at(kind<=3?Kind::Field:Kind::Method,r.u16());
                    require(r.u16()==0,"Invalid method handle padding.");
                    model.handles.push_back( {
                        kind,ref
                    });
                    auto symbol=textRef(Kind::Handle,{});
                    symbol->index=i;
                    refs[size_t(Kind::Handle)].push_back(symbol);
                }
            }
            if(maps.count(7)) {
                auto t=maps[7];
                Reader r(b,t.off);
                r.need(size_t(t.n)*4);
                for(uint32_t i=0;i<t.n;++i) {
                    Reader a(b,r.u32());
                    model.callsites.push_back(array(a,0));
                    auto symbol=textRef(Kind::Callsite,{});
                    symbol->index=i;
                    refs[size_t(Kind::Callsite)].push_back(symbol);
                }
            }
            Reader cr(b,tables[5].off);
            std::set<Text>seen;
            for(uint32_t i=0;i<tables[5].n;++i) {
                Class c;
                c.type=at(Kind::Type,cr.u32())->text;
                require(seen.insert(c.type).second,"Duplicate DEX class.");
                c.flags=cr.u32();
                auto sup=cr.u32();
                if(sup!=NONE)c.super=at(Kind::Type,sup)->text;
                c.interfaces=list(cr.u32());
                auto src=cr.u32();
                if(src!=NONE)c.source=at(Kind::String,src)->text;
                auto ann=cr.u32(),cd=cr.u32(),values=cr.u32();
                c.annotations=skipAnnotations?std::shared_ptr<Directory>{}:directory(ann);
                if(cd) {
                    Reader r(b,cd);
                    uint32_t counts[4];
                    for(auto& n:counts)n=r.count(r.u());
                    for(int g=0;g<4;++g) {
                        uint64_t index=0;
                        for(uint32_t j=0;j<counts[g];++j) {
                            index+=r.u();
                            require(index<=NONE,"Class member index overflow.");
                            auto ref=at(g<2?Kind::Field:Kind::Method,uint32_t(index));
                            auto flags=r.u();
                            require(ref->owner==c.type,"Class member has wrong owner.");
                            if(g<2) {
                                Field f {
                                    ref,flags,{}
                                };
                                (g==0?c.staticFields:c.instanceFields).push_back(f);
                            }
                            else {
                                auto codeItem=code(r.u());
                                (g==2?c.direct:c.virtuals).push_back(newMethod(ref,flags,codeItem));
                            }
                        }
                    }
                }
                if(values && !skipAnnotations) {
                    Reader r(b,values);
                    auto vals=array(r,0);
                    require(vals.size()<=c.staticFields.size(),"Invalid static field values.");
                    for(size_t j=0;j<vals.size();++j)c.staticFields[j].value=std::move(vals[j]);
                }
                model.classes.push_back(std::move(c));
            }
            return std::move(model);
        }
    };
    Model read(const Bytes& bytes, bool skipDebug, bool skipAnnotations) {
        Parser p(bytes);
        p.skipDebug = skipDebug;
        p.skipAnnotations = skipAnnotations;
        return p.parse();
    }
    std::vector<Text> classNames(const Bytes& bytes) {
        validateDex(bytes);
        Reader h(bytes,56);
        uint32_t stringCount=h.u32(), stringOff=h.u32();
        uint32_t typeCount=h.u32(), typeOff=h.u32();
        Reader cd(bytes,96);
        uint32_t classCount=cd.u32(), classOff=cd.u32();
        require(!stringCount||(stringOff>=112&&stringOff%4==0&&uint64_t(stringOff)+uint64_t(stringCount)*4<=bytes.size()),"Invalid DEX string table.");
        require(!typeCount||(typeOff>=112&&typeOff%4==0&&uint64_t(typeOff)+uint64_t(typeCount)*4<=bytes.size()),"Invalid DEX type table.");
        require(!classCount||(classOff>=112&&classOff%4==0&&uint64_t(classOff)+uint64_t(classCount)*32<=bytes.size()),"Invalid DEX class table.");
        std::vector<uint32_t> strings(stringCount),types(typeCount);
        Reader sr(bytes,stringOff);
        for(auto&v:strings)v=sr.u32();
        Reader tr(bytes,typeOff);
        for(auto&v:types)v=tr.u32();
        std::vector<Text> names;
        names.reserve(classCount);
        Reader cr(bytes,classOff);
        for(uint32_t i=0;i<classCount;++i) {
            cr.need(32);
            uint32_t typeIdx=cr.u32();
            cr.p+=28;
            require(typeIdx<typeCount,"Invalid DEX class type index.");
            uint32_t stringIdx=types[typeIdx];
            require(stringIdx<stringCount,"Invalid DEX class name index.");
            Reader name(bytes,strings[stringIdx]);
            names.push_back(mutfRead(name));
        }
        return names;
    }
}
