#include "bytes.hpp"
#include <cmath>
#include <random>
#include <zlib.h>
namespace dexpack {
    std::string utf8(const Text& s) {
        std::string out;
        for (size_t i = 0; i < s.size(); ++i) {
            uint32_t c = s[i];
            if (c >= 0xd800 && c <= 0xdbff) {
                if (i + 1 < s.size() && s[i+1] >= 0xdc00 && s[i+1] <= 0xdfff) {
                    c = 0x10000 + ((c - 0xd800) << 10) + s[++i] - 0xdc00;
                }
                else c = 0xfffd;
            }
            else if (c >= 0xdc00 && c <= 0xdfff) c = 0xfffd;
            if (c < 128) out += char(c);
            else if (c < 2048) {
                out += char(192 | (c >> 6));
                out += char(128 | (c & 63));
            }
            else if (c < 65536) {
                out += char(224 | (c >> 12));
                out += char(128 | ((c >> 6) & 63));
                out += char(128 | (c & 63));
            }
            else {
                out += char(240 | (c >> 18));
                out += char(128 | ((c >> 12) & 63));
                out += char(128 | ((c >> 6) & 63));
                out += char(128 | (c & 63));
            }
        }
        return out;
    }
    Text utf16(const std::string& s) {
        Text out;
        for (size_t i = 0; i < s.size();) {
            uint32_t a = uint8_t(s[i++]), c;
            unsigned n;
            if (a < 128) {
                c = a;
                n = 0;
            }
            else if ((a & 224) == 192) {
                c = a & 31;
                n = 1;
            }
            else if ((a & 240) == 224) {
                c = a & 15;
                n = 2;
            }
            else {
                require((a & 248) == 240, "Invalid UTF-8.");
                c = a & 7;
                n = 3;
            }
            require(i + n <= s.size(), "Truncated UTF-8.");
            for (unsigned k = 0; k < n; ++k) {
                auto b = uint8_t(s[i++]);
                require((b & 192) == 128, "Invalid UTF-8 continuation.");
                c = (c << 6) | (b & 63);
            }
            require(c <= 0x10ffff && !(c >= 0xd800 && c <= 0xdfff) && (n == 0 || c >= (n == 1 ? 128u : n == 2 ? 2048u : 65536u)), "Invalid UTF-8 code point.");
            if (c >= 65536) {
                c -= 65536;
                out += char16_t(0xd800 + (c >> 10));
                out += char16_t(0xdc00 + (c & 1023));
            }
            else out += char16_t(c);
        }
        return out;
    }
    bool validText(const Text& s) {
        for (size_t i = 0; i < s.size(); ++i) {
            auto c = s[i];
            if (c >= 0xd800 && c <= 0xdbff) {
                if (++i >= s.size() || s[i] < 0xdc00 || s[i] > 0xdfff) return false;
            }
            else if (c >= 0xdc00 && c <= 0xdfff) return false;
        }
        return true;
    }
    Text mutfRead(Reader& r) {
        auto count = r.count(r.u());
        Text s;
        s.reserve(count);
        for (;;) {
            uint32_t a = r.u8(), c = a;
            if (!a) break;
            if ((a & 224) == 192) {
                auto b = r.u8();
                require((b & 192) == 128, "Invalid DEX MUTF-8.");
                c = ((a & 31) << 6) | (b & 63);
            }
            else if ((a & 240) == 224) {
                auto b = r.u8(), d = r.u8();
                require((b & 192) == 128 && (d & 192) == 128, "Invalid DEX MUTF-8.");
                c = ((a & 15) << 12) | ((b & 63) << 6) | (d & 63);
            }
            else require(a < 128, "Invalid DEX MUTF-8.");
            s += char16_t(c);
            require(s.size() <= count, "Invalid DEX string length.");
        }
        require(s.size() == count, "Invalid DEX string length.");
        return s;
    }
    void mutfWrite(Writer& w, const Text& s) {
        w.u(narrow(s.size()));
        for (uint32_t c : s) {
            if (c && c < 128) w.u8(c);
            else if (c < 2048) w.u8(192 | (c >> 6)).u8(128 | (c & 63));
            else w.u8(224 | (c >> 12)).u8(128 | ((c >> 6) & 63)).u8(128 | (c & 63));
        }
        w.u8(0);
    }
    Bytes from64(const std::string& s) {
        const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        Bytes b;
        uint32_t buffer = 0;
        unsigned bits = 0;
        for (char c : s) {
            if (c == '=') break;
            auto pos = alphabet.find(c);
            if (pos == std::string::npos) {
                require(c == '\n' || c == '\r' || c == ' ', "Invalid Base64.");
                continue;
            }
            buffer = (buffer << 6) | uint32_t(pos);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                b.push_back(uint8_t(buffer >> bits));
            }
        }
        return b;
    }
    Bytes readFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        require(bool(f), "Cannot read file.");
        auto n = f.tellg();
        require(n >= 0, "Cannot read file size.");
        Bytes b(static_cast<size_t>(n));
        f.seekg(0);
        if (!b.empty()) f.read(reinterpret_cast<char*>(b.data()), std::streamsize(b.size()));
        require(bool(f), "Cannot read complete file.");
        return b;
    }
    void writeFile(const std::string& path, const Bytes& b) {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        require(bool(f), "Cannot create output file.");
        f.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
        f.close();
        require(bool(f), "Could not finish output; check free space.");
    }
    static uint32_t rot(uint32_t x, unsigned n) {
        return (x << n) | (x >> (32 - n));
    }
    Bytes md5(const Bytes& data) {
        Bytes b = data;
        b.push_back(128);
        while (b.size() % 64 != 56) b.push_back(0);
        uint64_t bits = uint64_t(data.size()) * 8;
        for (int i = 0; i < 8; ++i) b.push_back(uint8_t(bits >> (i*8)));
        std::array<uint32_t,4> h {
            0x67452301,0xefcdab89,0x98badcfe,0x10325476
        };
        static const auto k = [] {
            std::array<uint32_t,64> x{};
            for (int i = 0; i < 64; ++i) x[i] = uint32_t(std::floor(std::abs(std::sin(i+1.0))*4294967296.0));
            return x;
        }
        ();
        const unsigned r[] {
            7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21
        };
        for (size_t p = 0; p < b.size(); p += 64) {
            uint32_t a=h[0],c=h[1],d=h[2],e=h[3];
            for (unsigned i=0;i<64;++i) {
                uint32_t f,g;
                if(i<16) {
                    f=(c&d)|(~c&e);
                    g=i;
                }
                else if(i<32) {
                    f=(e&c)|(~e&d);
                    g=(5*i+1)%16;
                }
                else if(i<48) {
                    f=c^d^e;
                    g=(3*i+5)%16;
                }
                else {
                    f=d^(c|~e);
                    g=7*i%16;
                }
                auto next=c+rot(a+f+k[i]+get32(b,p+4*g),r[(i/16)*4+i%4]);
                a=e;
                e=d;
                d=c;
                c=next;
            }
            h[0]+=a;
            h[1]+=c;
            h[2]+=d;
            h[3]+=e;
        }
        Writer w;
        for(auto x:h)w.u32(x);
        return w.b;
    }
    Bytes sha1(const uint8_t* data, size_t size) {
        uint32_t h[] {
            0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0
        };
        auto process=[&](const uint8_t* block) {
            uint32_t w[80];
            for(int i=0;i<16;++i)w[i]=(uint32_t(block[4*i])<<24)|(uint32_t(block[4*i+1])<<16)|(uint32_t(block[4*i+2])<<8)|block[4*i+3];
            for(int i=16;i<80;++i)w[i]=rot(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
            uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
            for(int i=0;i<80;++i) {
                uint32_t f,k;
                if(i<20) {
                    f=(b&c)|(~b&d);
                    k=0x5a827999;
                }
                else if(i<40) {
                    f=b^c^d;
                    k=0x6ed9eba1;
                }
                else if(i<60) {
                    f=(b&c)|(b&d)|(c&d);
                    k=0x8f1bbcdc;
                }
                else {
                    f=b^c^d;
                    k=0xca62c1d6;
                }
                auto t=rot(a,5)+f+e+k+w[i];
                e=d;
                d=c;
                c=rot(b,30);
                b=a;
                a=t;
            }
            h[0]+=a;
            h[1]+=b;
            h[2]+=c;
            h[3]+=d;
            h[4]+=e;
        };
        size_t whole=size/64*64;
        for(size_t p=0;p<whole;p+=64)process(data+p);
        Bytes tail(data+whole,data+size);
        tail.push_back(128);
        while(tail.size()%64!=56)tail.push_back(0);
        uint64_t bits=uint64_t(size)*8;
        for(int i=7;i>=0;--i)tail.push_back(uint8_t(bits>>(8*i)));
        for(size_t p=0;p<tail.size();p+=64)process(tail.data()+p);
        Writer out;
        for(auto x:h)out.u8(x>>24).u8(x>>16).u8(x>>8).u8(x);
        return out.b;
    }
    static uint8_t mul(uint8_t a,uint8_t b) {
        uint8_t n=0;
        for(;b;b>>=1) {
            if(b&1)n^=a;
            a=uint8_t((a<<1)^((a&128)?0x11b:0));
        }
        return n;
    }
    Bytes aes128(const Bytes& data,const Bytes& key) {
        require(key.size()==16,"AES-128 key length.");
        static const auto s=[] {
            std::array<uint8_t,256> out{};
            for(unsigned x=0;x<256;++x) {
                uint8_t inv=x?1:0,a=uint8_t(x);
                for(unsigned n=254;x&&n;n>>=1) {
                    if(n&1)inv=mul(inv,a);
                    a=mul(a,a);
                }
                uint8_t y=inv;
                for(int n=1;n<=4;++n)y^=uint8_t((inv<<n)|(inv>>(8-n)));
                out[x]=y^99;
            }
            return out;
        }
        ();
        std::array<uint8_t,176>w{};
        std::copy(key.begin(),key.end(),w.begin());
        uint8_t rc=1;
        for(int p=16;p<176;p+=4) {
            std::array<uint8_t,4>t {
                w[p-4],w[p-3],w[p-2],w[p-1]
            };
            if(p%16==0) {
                t= {
                    uint8_t(s[t[1]]^rc),s[t[2]],s[t[3]],s[t[0]]
                };
                rc=mul(rc,2);
            }
            for(int j=0;j<4;++j)w[p+j]=w[p+j-16]^t[j];
        }
        Bytes out=data;
        auto padding=uint8_t(16-data.size()%16);
        out.insert(out.end(),padding,padding);
        for(size_t p=0;p<out.size();p+=16) {
            auto v=out.data()+p;
            for(int i=0;i<16;++i)v[i]^=w[i];
            for(int round=1;round<=10;++round) {
                std::array<uint8_t,16>shifted{};
                for(int i=0;i<16;++i)shifted[i]=s[v[i]];
                for(int c=0;c<4;++c)for(int r=0;r<4;++r)v[c*4+r]=shifted[((c+r)%4)*4+r];
                if(round<10)for(int c=0;c<16;c+=4) {
                    auto a=v[c],b=v[c+1],d=v[c+2],e=v[c+3];
                    v[c]=mul(a,2)^mul(b,3)^d^e;
                    v[c+1]=a^mul(b,2)^mul(d,3)^e;
                    v[c+2]=a^b^mul(d,2)^mul(e,3);
                    v[c+3]=mul(a,3)^b^d^mul(e,2);
                }
                for(int i=0;i<16;++i)v[i]^=w[round*16+i];
            }
        }
        return out;
    }
    Text encryptString(const Text& value,const Text& password) {
        auto key=ascii(hex(md5(ascii(utf8(password)))).substr(8,16));
        return utf16("Fallen-"+hex(aes128(ascii(utf8(value)),key)));
    }
    static uint32_t checksum(const Bytes& b,size_t start) {
        uLong sum=adler32(0L,Z_NULL,0);
        for(size_t p=start;p<b.size();) {
            auto n=std::min<size_t>(b.size()-p,1024*1024);
            sum=adler32(sum,b.data()+p,uInt(n));
            p+=n;
        }
        return uint32_t(sum);
    }
    void fixDex(Bytes& b) {
        require(b.size()>=112,"Truncated DEX header.");
        put32(b,32,narrow(b.size()));
        auto hash=sha1(b.data()+32,b.size()-32);
        std::copy(hash.begin(),hash.end(),b.begin()+12);
        put32(b,8,checksum(b,12));
    }
    void validateDex(const Bytes& b) {
        require(b.size()>=112&&std::memcmp(b.data(),"dex\n",4)==0&&b[7]==0,"Invalid DEX header.");
        std::string v(b.begin()+4,b.begin()+7);
        require(v=="035"||v=="036"||v=="037"||v=="038"||v=="039"||v=="040","Unsupported DEX version.");
        require(get32(b,32)==b.size()&&get32(b,36)==112&&get32(b,40)==0x12345678,"Invalid DEX bounds.");
        auto hash=sha1(b.data()+32,b.size()-32);
        require(std::equal(hash.begin(),hash.end(),b.begin()+12)&&checksum(b,12)==get32(b,8),"Corrupt DEX checksum.");
    }
    std::string randomToken() {
        Bytes b(8);
        std::ifstream f("/dev/urandom",std::ios::binary);
        if(f) {
            f.read(reinterpret_cast<char*>(b.data()),8);
            require(bool(f),"Random source failed.");
        }
        else {
            std::random_device r;
            for(auto& v:b)v=uint8_t(r());
        }
        return hex(b);
    }
}
