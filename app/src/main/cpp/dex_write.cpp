#include "dex.hpp"
namespace dexpack::dex {
    struct Index {
        std::array<std::map<Text,Ref>,6> sets;
        std::array<std::vector<Ref>,6> lists;
        std::array<std::map<Text,uint32_t>,6> ids;
        std::vector<Ann> annotations;
        std::vector<AnnSet> annSets;
        std::vector<AnnParams> annParams;
        std::vector<std::shared_ptr<Directory>> directories;
        std::set<const void*> seen;
        void add(const Ref& r) {
            if(!r||r->kind==Kind::None||r->kind==Kind::Handle||r->kind==Kind::Callsite)return;
            auto k=size_t(r->kind);
            if(!sets[k].emplace(key(r),r).second)return;
            if(r->kind==Kind::Type)add(textRef(Kind::String,r->text));
            if(r->kind==Kind::Proto) {
                add(textRef(Kind::Type,r->type));
                for(const auto&t:r->params)add(textRef(Kind::Type,t));
                add(textRef(Kind::String,shorty(r)));
            }
            if(r->kind==Kind::Field) {
                add(textRef(Kind::Type,r->owner));
                add(textRef(Kind::Type,r->type));
                add(textRef(Kind::String,r->text));
            }
            if(r->kind==Kind::Method) {
                add(textRef(Kind::Type,r->owner));
                add(textRef(Kind::String,r->text));
                add(r->proto);
            }
        }
        void addText(Kind kind,const Text& text) {
            add(textRef(kind,text));
        }
        void optional(Kind kind,const std::optional<Text>& text) {
            if(text)addText(kind,*text);
        }
        void value(const Value& v) {
            add(v.ref);
            for(const auto&x:v.items)value(x);
            if(v.annotation)annotation(v.annotation);
        }
        void annotation(const Ann& a) {
            require(bool(a),"Missing annotation.");
            addText(Kind::Type,a->type);
            for(const auto&p:a->items) {
                addText(Kind::String,p.first);
                value(p.second);
            }
        }
        void aset(const AnnSet& a) {
            if(!a||!seen.insert(a.get()).second)return;
            annSets.push_back(a);
            for(const auto&x:*a) {
                if(seen.insert(x.get()).second) {
                    annotations.push_back(x);
                    annotation(x);
                }
            }
        }
        void directory(const std::shared_ptr<Directory>& a) {
            if(!a||!seen.insert(a.get()).second)return;
            directories.push_back(a);
            aset(a->cls);
            for(const auto&p:a->fields) {
                add(p.first);
                aset(p.second);
            }
            for(const auto&p:a->methods) {
                add(p.first);
                aset(p.second);
            }
            for(const auto&p:a->params) {
                add(p.first);
                if(p.second&&seen.insert(p.second.get()).second) {
                    annParams.push_back(p.second);
                    for(const auto&s:*p.second)aset(s);
                }
            }
        }
        explicit Index(const Model& model) {
            for(const auto&h:model.handles)add(h.ref);
            for(const auto&a:model.callsites)for(const auto&v:a)value(v);
            for(const auto&c:model.classes) {
                addText(Kind::Type,c.type);
                optional(Kind::Type,c.super);
                optional(Kind::String,c.source);
                for(const auto&t:c.interfaces)addText(Kind::Type,t);
                directory(c.annotations);
                for(const auto*g: {
                    &c.staticFields,&c.instanceFields
                })for(const auto&f:*g) {
                    add(f.ref);
                    if(f.value)value(*f.value);
                }
                for(const auto*g: {
                    &c.direct,&c.virtuals
                })for(const auto&m:*g) {
                    add(m->ref);
                    if(!m->code)continue;
                    for(const auto&i:m->code->instructions) {
                        add(i.ref);
                        add(i.proto);
                    }
                    for(const auto&t:m->code->tries)for(const auto&p:t.handler->types)addText(Kind::Type,p.first);
                    if(m->code->debug) {
                        for(const auto&s:m->code->debug->params)optional(Kind::String,s);
                        for(const auto&e:m->code->debug->events) {
                            optional(Kind::String,e.name);
                            optional(Kind::String,e.sig);
                            optional(Kind::String,e.file);
                            optional(Kind::Type,e.type);
                        }
                    }
                }
            }
            auto sort=[&](Kind kind,auto cmp) {
                auto k=size_t(kind);
                auto&a=lists[k];
                for(const auto&p:sets[k])a.push_back(p.second);
                std::sort(a.begin(),a.end(),cmp);
                for(size_t i=0;i<a.size();++i)ids[k][key(a[i])]=narrow(i);
            };
            sort(Kind::String,[](const Ref&a,const Ref&b) {
                return a->text<b->text;
            });
            sort(Kind::Type,[&](const Ref&a,const Ref&b) {
                return id(Kind::String,a->text)<id(Kind::String,b->text);
            });
            sort(Kind::Proto,[&](const Ref&a,const Ref&b) {
                auto x=id(Kind::Type,a->type),y=id(Kind::Type,b->type);if(x!=y)return x<y;return std::lexicographical_compare(a->params.begin(),a->params.end(),b->params.begin(),b->params.end(),[&](const Text&p,const Text&q) {
                    return id(Kind::Type,p)<id(Kind::Type,q);
                });
            });
            sort(Kind::Field,[&](const Ref&a,const Ref&b) {
                return std::make_tuple(id(Kind::Type,a->owner),id(Kind::String,a->text),id(Kind::Type,a->type))<std::make_tuple(id(Kind::Type,b->owner),id(Kind::String,b->text),id(Kind::Type,b->type));
            });
            sort(Kind::Method,[&](const Ref&a,const Ref&b) {
                return std::make_tuple(id(Kind::Type,a->owner),id(Kind::String,a->text),id(a->proto))<std::make_tuple(id(Kind::Type,b->owner),id(Kind::String,b->text),id(b->proto));
            });
            require(lists[2].size()<=65535&&lists[3].size()<=65535&&lists[4].size()<=65536&&lists[5].size()<=65536&&model.handles.size()<=65536&&model.callsites.size()<=65536,"DEX reference table overflow; select fewer classes.");
        }
        uint32_t id(Kind kind,const Text& k)const {
            const auto&m=ids[size_t(kind)];
            auto it=m.find(k);
            require(it!=m.end(),"Unresolved DEX reference.");
            return it->second;
        }
        uint32_t id(const Ref&r)const {
            require(bool(r),"Missing DEX symbol.");
            return r->kind==Kind::Handle||r->kind==Kind::Callsite?r->index:id(r->kind,key(r));
        }
        uint32_t opt(Kind k,const std::optional<Text>&s)const {
            return s?id(k,*s)+1:0;
        }
    };
    struct Relocated {
        const Code& code;
        const Index& index;
        std::vector<Instruction> instructions;
        std::map<uint32_t,uint32_t> positions;
        std::vector<uint32_t> boundaries;
        std::vector<uint16_t> units;
        std::vector<Try> tries;
        Bytes debug;
        uint32_t pos(uint32_t old)const {
            auto p=positions.find(old);
            require(p!=positions.end(),"Invalid relocated DEX address.");
            return p->second;
        }
        uint32_t debugPos(uint32_t old)const {
            auto it=positions.find(old);
            if(it!=positions.end())return it->second;
            require(old<code.oldSize,"Invalid DEX debug address.");
            it=positions.upper_bound(old);
            require(it!=positions.begin(),"Invalid DEX debug position.");
            return (--it)->second;
        }
        Relocated(const Code& c,const Index& idx):code(c),index(idx),instructions(c.instructions) {
            for(auto&i:instructions)i.width=i.payload?narrow(i.units.size()):(i.op==26||i.op==27||i.op==40||i.op==41||i.op==42)?3:narrow(i.units.size());
            for(size_t round=0;;++round) {
                require(round<=instructions.size()+1,"Cannot relocate DEX branches.");
                positions.clear();
                uint64_t pc=0;
                for(auto&i:instructions) {
                    if(i.payload&&pc%2)++pc;
                    i.pc=narrow(pc);
                    if(i.oldPc>=0)require(positions.emplace(uint32_t(i.oldPc),i.pc).second,"Duplicate DEX relocation anchor.");
                    pc+=i.width;
                }
                positions[c.oldSize]=narrow(pc);
                bool changed=false;
                for(auto&i:instructions)if(i.target>=0&&i.op>=0x32&&i.op<=0x3d&&i.width==2) {
                    int64_t delta=int64_t(pos(uint32_t(i.target)))-i.pc;
                    if(delta<-32768||delta>32767) {
                        i.width=5;
                        changed=true;
                    }
                }
                if(!changed)break;
            }
            std::map<uint32_t,std::vector<int64_t>>payloadTargets;
            for(const auto&i:instructions)if(i.op==43||i.op==44) {
                std::vector<int64_t>targets;
                for(auto t:i.cases)targets.push_back(int64_t(pos(t))-i.pc);
                auto it=payloadTargets.find(uint32_t(i.target));
                require(it==payloadTargets.end()||it->second==targets,"Shared switch payload needs separate relocation.");
                payloadTargets[uint32_t(i.target)]=targets;
            }
            for(const auto&i:instructions) {
                while(units.size()<i.pc)units.push_back(0);
                auto u=i.units;
                if(i.op==26||i.op==27) {
                    auto n=idx.id(i.ref);
                    u= {
                        uint16_t(0x1b|(u[0]&0xff00)),uint16_t(n),uint16_t(n>>16)
                    };
                }
                else if(i.ref) {
                    auto n=idx.id(i.ref);
                    require(n<=65535,"DEX instruction reference overflow.");
                    u[1]=uint16_t(n);
                    if(i.proto)u[3]=uint16_t(idx.id(i.proto));
                }
                if(i.target>=0) {
                    int64_t delta=int64_t(pos(uint32_t(i.target)))-i.pc;
                    require(delta>=std::numeric_limits<int32_t>::min()&&delta<=std::numeric_limits<int32_t>::max(),"DEX branch offset overflow.");
                    if(i.op==40||i.op==41||i.op==42)u= {
                        42,uint16_t(delta),uint16_t(uint64_t(delta)>>16)
                    };
                    else if(i.op>=0x32&&i.op<=0x3d) {
                        if(i.width==5) {
                            auto d=int64_t(pos(uint32_t(i.target)))-(i.pc+2);
                            u= {
                                uint16_t((u[0]&0xff00)|(((i.op-0x32)^1)+0x32)),5,42,uint16_t(d),uint16_t(uint64_t(d)>>16)
                            };
                        }
                        else u[1]=uint16_t(delta);
                    }
                    else {
                        u[1]=uint16_t(delta);
                        u[2]=uint16_t(uint64_t(delta)>>16);
                    }
                }
                if(i.payload==256||i.payload==512) {
                    auto it=payloadTargets.find(uint32_t(i.oldPc));
                    require(it!=payloadTargets.end(),"Unreferenced switch payload.");
                    size_t base=i.payload==256?4:2+2*u[1];
                    for(size_t j=0;j<it->second.size();++j) {
                        auto t=it->second[j];
                        u[base+2*j]=uint16_t(t);
                        u[base+2*j+1]=uint16_t(uint64_t(t)>>16);
                    }
                }
                require(u.size()==i.width,"Invalid relocated instruction width.");
                boundaries.push_back(i.pc);
                units.insert(units.end(),u.begin(),u.end());
            }
            for(const auto&t:c.tries) {
                auto start=pos(t.start),end=pos(t.start+t.length);
                while(end-start>65535) {
                    auto it=std::upper_bound(boundaries.begin(),boundaries.end(),start+65535);
                    require(it!=boundaries.begin(),"Cannot split DEX try range.");
                    auto split=*--it;
                    require(split>start,"Cannot split DEX try range.");
                    tries.push_back( {
                        start,split-start,t.handler
                    });
                    start=split;
                }
                if(end>start)tries.push_back( {
                    start,end-start,t.handler
                });
            }
            require(tries.size()<=65535,"Too many DEX try ranges.");
            if(c.debug) {
                Writer w;
                const auto&d=*c.debug;
                w.u(d.line).u(narrow(d.params.size()));
                for(const auto&p:d.params)w.u(idx.opt(Kind::String,p));
                uint32_t pc=0;
                if(pos(0)) {
                    w.u8(1).u(pos(0));
                    pc=pos(0);
                }
                for(const auto&e:d.events) {
                    if(e.op==1||e.op>=10) {
                        auto next=debugPos(e.pc);
                        require(next>=pc,"Invalid DEX debug order.");
                        if(next!=pc)w.u8(1).u(next-pc);
                        pc=next;
                        if(e.op>=10)w.u8(uint32_t(14+e.line));
                    }
                    else {
                        w.u8(e.op);
                        if(e.op==2)w.s(e.line);
                        if(e.op==3||e.op==4) {
                            w.u(e.reg).u(idx.opt(Kind::String,e.name)).u(idx.opt(Kind::Type,e.type));
                            if(e.op==4)w.u(idx.opt(Kind::String,e.sig));
                        }
                        if(e.op==5||e.op==6)w.u(e.reg);
                        if(e.op==9)w.u(idx.opt(Kind::String,e.file));
                    }
                }
                w.u8(0);
                debug=std::move(w.b);
            }
        }
        Bytes bytes(uint32_t debugOffset)const {
            Writer w;
            require(code.registers<=65535&&code.ins<=code.registers&&code.outs<=65535,"DEX frame overflow.");
            w.u16(code.registers).u16(code.ins).u16(code.outs).u16(narrow(tries.size())).u32(debugOffset).u32(narrow(units.size()));
            for(auto u:units)w.u16(u);
            if(!tries.empty()) {
                if(units.size()%2)w.u16(0);
                std::vector<std::shared_ptr<Handler>>hs;
                std::set<Handler*>seen;
                for(const auto&t:tries)if(seen.insert(t.handler.get()).second)hs.push_back(t.handler);
                Writer hw;
                hw.u(narrow(hs.size()));
                std::map<Handler*,uint32_t>offsets;
                for(const auto&h:hs) {
                    offsets[h.get()]=hw.size();
                    auto n=int32_t(h->types.size());
                    hw.s(h->catchAll?-n:n);
                    for(const auto&p:h->types)hw.u(index.id(Kind::Type,p.first)).u(pos(p.second));
                    if(h->catchAll)hw.u(pos(*h->catchAll));
                }
                for(const auto&t:tries) {
                    auto off=offsets[t.handler.get()];
                    require(off<=65535,"DEX handler offset overflow.");
                    w.u32(t.start).u16(t.length).u16(off);
                }
                w.bytes(hw.b);
            }
            return w.b;
        }
    };
    struct Serializer {
        const Model& model;
        Index index;
        struct Map {
            uint16_t type;
            uint32_t count,offset;
        };
        std::vector<Map> maps {
            {
                0,1,0
            }
        };
        Writer body;
        std::array<uint32_t,6> offsets{},counts{};
        uint32_t callOff=0,handleOff=0,start=112;
        explicit Serializer(const Model&m):model(m),index(m) {
            const uint32_t widths[] {
                4,4,12,8,8,32
            };
            for(size_t i=0;i<6;++i) {
                auto n=i==5?narrow(m.classes.size()):narrow(index.lists[i+1].size());
                counts[i]=n;
                offsets[i]=n?start:0;
                if(n)maps.push_back( {
                    uint16_t(i+1),n,start
                });
                start=narrow(uint64_t(start)+uint64_t(n)*widths[i]);
            }
            if(!m.callsites.empty()) {
                callOff=start;
                maps.push_back( {
                    7,narrow(m.callsites.size()),start
                });
                start=narrow(uint64_t(start)+m.callsites.size()*4);
            }
            if(!m.handles.empty()) {
                handleOff=start;
                maps.push_back( {
                    8,narrow(m.handles.size()),start
                });
                start=narrow(uint64_t(start)+m.handles.size()*8);
            }
            start=(start+3)&~uint32_t(3);
            body.base=start;
        }
        template<typename T,typename F>void section(uint16_t type,const std::vector<T>&items,F fn,bool aligned=false) {
            if(items.empty())return;
            size_t map=maps.size();
            maps.push_back( {
                type,narrow(items.size()),0
            });
            for(size_t i=0;i<items.size();++i) {
                if(aligned)body.align();
                if(i==0)maps[map].offset=body.size();
                fn(items[i],body.size());
            }
        }
        void value(Writer&w,const Value&v) {
            if(v.ref) {
                auto n=index.id(v.ref);
                Bytes raw;
                do {
                    raw.push_back(uint8_t(n));
                    n>>=8;
                }
                while(n);
                w.u8(v.type|uint32_t((raw.size()-1)<<5)).bytes(raw);
            }
            else if(v.type==28) {
                w.u8(28);
                array(w,v.items);
            }
            else if(v.type==29) {
                w.u8(29);
                annotation(w,v.annotation);
            }
            else if(v.type==30||v.type==31)w.u8(v.type|(v.arg<<5));
            else {
                require(!v.raw.empty()&&v.raw.size()<=8,"Invalid encoded primitive.");
                w.u8(v.type|uint32_t((v.raw.size()-1)<<5)).bytes(v.raw);
            }
        }
        void array(Writer&w,const std::vector<Value>&a) {
            w.u(narrow(a.size()));
            for(const auto&v:a)value(w,v);
        }
        void annotation(Writer&w,const Ann&a) {
            w.u(index.id(Kind::Type,a->type)).u(narrow(a->items.size()));
            auto items=a->items;
            std::sort(items.begin(),items.end(),[&](const auto&x,const auto&y) {
                return index.id(Kind::String,x.first)<index.id(Kind::String,y.first);
            });
            for(const auto&p:items) {
                w.u(index.id(Kind::String,p.first));
                value(w,p.second);
            }
        }
        Bytes run() {
            std::vector<uint32_t>stringOff;
            section(0x2002,index.lists[1],[&](const Ref&r,uint32_t off) {
                stringOff.push_back(off);mutfWrite(body,r->text);
            });
            std::set<std::vector<Text>>listSet;
            for(const auto&p:index.lists[3])if(!p->params.empty())listSet.insert(p->params);
            for(const auto&c:model.classes)if(!c.interfaces.empty())listSet.insert(c.interfaces);
            std::vector<std::vector<Text>>lists(listSet.begin(),listSet.end());
            std::map<std::vector<Text>,uint32_t>listOff;
            section(0x1001,lists,[&](const auto&a,uint32_t off) {
                listOff[a]=off;body.u32(narrow(a.size()));for(const auto&t:a)body.u16(index.id(Kind::Type,t));
            },true);
            std::vector<std::shared_ptr<Code>>codes;
            std::set<Code*>seen;
            for(const auto&c:model.classes)for(const auto*g: {
                &c.direct,&c.virtuals
            })for(const auto&m:*g)if(m->code&&seen.insert(m->code.get()).second)codes.push_back(m->code);
            std::map<Code*,std::unique_ptr<Relocated>>relocated;
            std::vector<std::shared_ptr<Code>>debugCodes;
            for(const auto&c:codes) {
                relocated[c.get()]=std::make_unique<Relocated>(*c,index);
                if(c->debug)debugCodes.push_back(c);
            }
            std::map<Code*,uint32_t>debugOff,codeOff;
            section(0x2003,debugCodes,[&](const auto&c,uint32_t off) {
                debugOff[c.get()]=off;body.bytes(relocated[c.get()]->debug);
            });
            section(0x2001,codes,[&](const auto&c,uint32_t off) {
                codeOff[c.get()]=off;body.bytes(relocated[c.get()]->bytes(debugOff[c.get()]));
            },true);
            std::vector<const Class*>classes;
            for(const auto&c:model.classes)if(!c.staticFields.empty()||!c.instanceFields.empty()||!c.direct.empty()||!c.virtuals.empty())classes.push_back(&c);
            std::map<const Class*,uint32_t>classData;
            section(0x2000,classes,[&](const Class*c,uint32_t off) {
                classData[c]=off;body.u(narrow(c->staticFields.size())).u(narrow(c->instanceFields.size())).u(narrow(c->direct.size())).u(narrow(c->virtuals.size()));for(const auto*g: {
                    &c->staticFields,&c->instanceFields
                }) {
                    auto a=*g;std::sort(a.begin(),a.end(),[&](const Field&x,const Field&y) {
                        return index.id(x.ref)<index.id(y.ref);
                    });uint32_t prev=0;for(const auto&f:a) {
                        auto n=index.id(f.ref);body.u(n-prev).u(f.flags);prev=n;
                    }
                }
                for(const auto*g: {
                    &c->direct,&c->virtuals
                }) {
                    auto a=*g;std::sort(a.begin(),a.end(),[&](const auto&x,const auto&y) {
                        return index.id(x->ref)<index.id(y->ref);
                    });uint32_t prev=0;for(const auto&m:a) {
                        auto n=index.id(m->ref);body.u(n-prev).u(m->flags).u(m->code?codeOff[m->code.get()]:0);prev=n;
                    }
                }
            });
            std::map<const void*,uint32_t>annOff,setOff,paramOff,dirOff;
            section(0x2004,index.annotations,[&](const Ann&a,uint32_t off) {
                annOff[a.get()]=off;body.u8(a->visibility);annotation(body,a);
            });
            section(0x1003,index.annSets,[&](const AnnSet&a,uint32_t off) {
                setOff[a.get()]=off;body.u32(narrow(a->size()));auto items=*a;std::sort(items.begin(),items.end(),[&](const Ann&x,const Ann&y) {
                    return index.id(Kind::Type,x->type)<index.id(Kind::Type,y->type);
                });for(const auto&x:items)body.u32(annOff[x.get()]);
            },true);
            section(0x1002,index.annParams,[&](const AnnParams&a,uint32_t off) {
                paramOff[a.get()]=off;body.u32(narrow(a->size()));for(const auto&x:*a)body.u32(x?setOff[x.get()]:0);
            },true);
            section(0x2006,index.directories,[&](const auto&a,uint32_t off) {
                dirOff[a.get()]=off;body.u32(a->cls?setOff[a->cls.get()]:0).u32(narrow(a->fields.size())).u32(narrow(a->methods.size())).u32(narrow(a->params.size()));auto pairs=[&](auto v,const auto&offs) {
                    std::sort(v.begin(),v.end(),[&](const auto&x,const auto&y) {
                        return index.id(x.first)<index.id(y.first);
                    });for(const auto&p:v) {
                        auto it=offs.find(p.second.get());body.u32(index.id(p.first)).u32(p.second&&it!=offs.end()?it->second:0);
                    }
                };pairs(a->fields,setOff);pairs(a->methods,setOff);pairs(a->params,paramOff);
            },true);
            std::vector<std::vector<Value>>arrays=model.callsites;
            std::map<const Class*,size_t>staticArray;
            for(const auto&c:model.classes) {
                auto fields=c.staticFields;
                std::sort(fields.begin(),fields.end(),[&](const Field&a,const Field&b) {
                    return index.id(a.ref)<index.id(b.ref);
                });
                size_t end=0;
                for(size_t i=0;i<fields.size();++i)if(fields[i].value)end=i+1;
                if(!end)continue;
                std::vector<Value>a;
                for(size_t i=0;i<end;++i) {
                    const auto&f=fields[i];
                    if(f.value)a.push_back(*f.value);
                    else {
                        Value v;
                        require(!f.ref->type.empty(),"Empty field type.");
                        auto t=f.ref->type[0];
                        if(t!=u'L'&&t!=u'[') {
                            v.type=t==u'Z'?31:t==u'J'?6:t==u'D'?17:t==u'F'?16:t==u'B'?0:t==u'S'?2:t==u'C'?3:4;
                            v.raw= {
                                0
                            };
                        }
                        a.push_back(v);
                    }
                }
                staticArray[&c]=arrays.size();
                arrays.push_back(std::move(a));
            }
            std::vector<uint32_t>arrayOff;
            section(0x2005,arrays,[&](const auto&a,uint32_t off) {
                arrayOff.push_back(off);array(body,a);
            });
            body.align();
            auto mapOff=body.size();
            maps.push_back( {
                0x1000,1,mapOff
            });
            std::sort(maps.begin(),maps.end(),[](const Map&a,const Map&b) {
                return a.offset<b.offset;
            });
            body.u32(narrow(maps.size()));
            for(const auto&m:maps)body.u16(m.type).u16(0).u32(m.count).u32(m.offset);
            Bytes out(start,0);
            std::string magic="dex\n"+model.version;
            std::copy(magic.begin(),magic.end(),out.begin());
            put32(out,32,body.size());
            put32(out,36,112);
            put32(out,40,0x12345678);
            put32(out,52,mapOff);
            for(size_t i=0;i<6;++i) {
                put32(out,56+8*i,counts[i]);
                put32(out,60+8*i,offsets[i]);
            }
            put32(out,104,body.size()-start);
            put32(out,108,start);
            for(size_t i=0;i<stringOff.size();++i)put32(out,offsets[0]+4*i,stringOff[i]);
            for(size_t i=0;i<index.lists[2].size();++i)put32(out,offsets[1]+4*i,index.id(Kind::String,index.lists[2][i]->text));
            for(size_t i=0;i<index.lists[3].size();++i) {
                const auto&p=index.lists[3][i];
                auto off=offsets[2]+12*i;
                put32(out,off,index.id(Kind::String,shorty(p)));
                put32(out,off+4,index.id(Kind::Type,p->type));
                put32(out,off+8,p->params.empty()?0:listOff[p->params]);
            }
            for(size_t i=0;i<index.lists[4].size();++i) {
                const auto&f=index.lists[4][i];
                auto off=offsets[3]+8*i;
                put16(out,off,index.id(Kind::Type,f->owner));
                put16(out,off+2,index.id(Kind::Type,f->type));
                put32(out,off+4,index.id(Kind::String,f->text));
            }
            for(size_t i=0;i<index.lists[5].size();++i) {
                const auto&m=index.lists[5][i];
                auto off=offsets[4]+8*i;
                put16(out,off,index.id(Kind::Type,m->owner));
                put16(out,off+2,index.id(m->proto));
                put32(out,off+4,index.id(Kind::String,m->text));
            }
            std::vector<const Class*>sorted;
            for(const auto&c:model.classes)sorted.push_back(&c);
            std::sort(sorted.begin(),sorted.end(),[&](const Class*a,const Class*b) {
                return index.id(Kind::Type,a->type)<index.id(Kind::Type,b->type);
            });
            for(size_t i=0;i<sorted.size();++i) {
                const auto&c=*sorted[i];
                auto off=offsets[5]+32*i;
                uint32_t values[] {
                    index.id(Kind::Type,c.type),c.flags,c.super?index.id(Kind::Type,*c.super):NONE,c.interfaces.empty()?0:listOff[c.interfaces],c.source?index.id(Kind::String,*c.source):NONE,c.annotations?dirOff[c.annotations.get()]:0,classData[&c],staticArray.count(&c)?arrayOff[staticArray[&c]]:0
                };
                for(size_t j=0;j<8;++j)put32(out,off+4*j,values[j]);
            }
            for(size_t i=0;i<model.callsites.size();++i)put32(out,callOff+4*i,arrayOff[i]);
            for(size_t i=0;i<model.handles.size();++i) {
                const auto&h=model.handles[i];
                put16(out,handleOff+8*i,h.kind);
                put16(out,handleOff+8*i+4,index.id(h.ref));
            }
            out.insert(out.end(),body.b.begin(),body.b.end());
            fixDex(out);
            return out;
        }
    };
    Bytes write(const Model& model) {
        return Serializer(model).run();
    }
    void rename(Model& model,const Text&before,const Text&after) {
        std::set<const void*>seen;
        auto text=[&](Text&s) {
            if(s==before)s=after;
        };
        auto optional=[&](std::optional<Text>&s) {
            if(s)text(*s);
        };
        std::function<void(Ref&)>ref=[&](Ref&r) {
            if(!r||!seen.insert(r.get()).second)return;
            text(r->text);
            text(r->owner);
            text(r->type);
            for(auto&p:r->params)text(p);
            ref(r->proto);
        };
        std::function<void(Value&)>value;
        std::function<void(Ann&)>ann=[&](Ann&a) {
            if(!a||!seen.insert(a.get()).second)return;
            text(a->type);
            for(auto&p:a->items) {
                text(p.first);
                value(p.second);
            }
        };
        value=[&](Value&v) {
            ref(v.ref);
            for(auto&x:v.items)value(x);
            ann(v.annotation);
        };
        auto aset=[&](AnnSet&a) {
            if(a)for(auto&x:*a)ann(x);
        };
        for(auto&h:model.handles)ref(h.ref);
        for(auto&a:model.callsites)for(auto&v:a)value(v);
        for(auto&c:model.classes) {
            text(c.type);
            optional(c.super);
            optional(c.source);
            for(auto&t:c.interfaces)text(t);
            if(c.annotations) {
                auto&a=*c.annotations;
                aset(a.cls);
                for(auto*g: {
                    &a.fields,&a.methods
                })for(auto&p:*g) {
                    ref(p.first);
                    aset(p.second);
                }
                for(auto&p:a.params) {
                    ref(p.first);
                    if(p.second)for(auto&s:*p.second)aset(s);
                }
            }
            for(auto*g: {
                &c.staticFields,&c.instanceFields
            })for(auto&f:*g) {
                ref(f.ref);
                if(f.value)value(*f.value);
            }
            for(auto*g: {
                &c.direct,&c.virtuals
            })for(auto&m:*g) {
                ref(m->ref);
                if(!m->code||!seen.insert(m->code.get()).second)continue;
                auto&code=*m->code;
                for(auto&i:code.instructions) {
                    ref(i.ref);
                    ref(i.proto);
                }
                for(auto&t:code.tries)for(auto&p:t.handler->types)text(p.first);
                if(code.debug) {
                    for(auto&s:code.debug->params)optional(s);
                    for(auto&e:code.debug->events) {
                        optional(e.name);
                        optional(e.type);
                        optional(e.sig);
                        optional(e.file);
                    }
                }
            }
        }
    }
}
