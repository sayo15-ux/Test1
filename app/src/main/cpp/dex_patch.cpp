#include "dex.hpp"
#include <algorithm>
#include <cstring>
#include <unordered_map>
namespace dexpack::dex {
namespace {
struct R{ const Bytes& b; size_t p=0; void need(size_t n){ if(p+n>b.size()) throw std::runtime_error("DEX patch read"); }
uint8_t u8(){ need(1); return b[p++]; }
uint16_t u16(){ need(2); uint16_t v=uint16_t(b[p])|uint16_t(b[p+1])<<8; p+=2; return v; }
uint32_t u32(){ need(4); uint32_t v=uint32_t(b[p])|(uint32_t(b[p+1])<<8)|(uint32_t(b[p+2])<<16)|(uint32_t(b[p+3])<<24); p+=4; return v; }
uint32_t uleb(){ uint32_t r=0,s=0; for(int i=0;i<5;++i){ uint8_t x=u8(); r|=uint32_t(x&0x7f)<<s; if(!(x&0x80)) return r; s+=7; } throw std::runtime_error("uleb"); }
int32_t sleb(){ int32_t r=0,s=0; uint8_t x=0; for(int i=0;i<5;++i){ x=u8(); r|=int32_t(x&0x7f)<<s; s+=7; if(!(x&0x80)) break; } if(s<32 && (x&0x40)) r|= - (1<<s); return r; }
};
struct W{ Bytes b; void u8(uint8_t v){ b.push_back(v); } void u16(uint16_t v){ b.push_back(uint8_t(v)); b.push_back(uint8_t(v>>8)); }
void u32(uint32_t v){ for(int i=0;i<4;++i) b.push_back(uint8_t(v>>(8*i))); }
void uleb(uint32_t v){ for(;;){ uint8_t x=v&0x7f; v>>=7; if(v){ b.push_back(x|0x80);} else { b.push_back(x); break; } } }
void sleb(int32_t v){ bool more=true; while(more){ uint8_t x=v&0x7f; int32_t sign=x&0x40; v>>=7; if((v==0 && !sign)||(v==-1 && sign)) more=false; b.push_back(more?x|0x80:x); } }
void bytes(const uint8_t* p,size_t n){ b.insert(b.end(),p,p+n); }
};
static std::string mutf8(const Bytes& b,size_t off){
    R r{b,off}; uint32_t len=r.uleb(); std::string s; s.reserve(len);
    for(uint32_t i=0;i<len;++i){ uint8_t c=r.u8(); if((c&0x80)==0) s.push_back(char(c));
      else if((c&0xe0)==0xc0){ uint8_t c2=r.u8(); s.push_back(char(((c&0x1f)<<6)|(c2&0x3f))); }
      else { uint8_t c2=r.u8(),c3=r.u8(); uint32_t cp=((c&0x0f)<<12)|((c2&0x3f)<<6)|(c3&0x3f); if(cp>=0x0800) { /* keep as utf8 */ char buf[4]; int n=0; if(cp<0x10000){ buf[0]=char(0xe0|(cp>>12)); buf[1]=char(0x80|((cp>>6)&0x3f)); buf[2]=char(0x80|(cp&0x3f)); n=3; } s.append(buf,n);} }
    }
    return s;
}
static void putMutf8(W& w,const std::string& s){ /* s is utf8-ish ascii mostly */ w.uleb((uint32_t)s.size()); w.bytes((const uint8_t*)s.data(),s.size()); w.u8(0); }
}
}
