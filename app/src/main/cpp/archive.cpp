#include "archive.hpp"
#include <cctype>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <zlib.h>
namespace dexpack {
    struct ArchiveFile {
        int fd;
        explicit ArchiveFile(const std::string& path) : fd(open64(path.c_str(), O_RDONLY | O_CLOEXEC)) { require(fd >= 0, "Cannot open APK."); }
        ~ArchiveFile() { close(fd); }
        ArchiveFile(const ArchiveFile&) = delete;
        void read(uint64_t offset, uint8_t* data, size_t size) {
            while (size) {
                ssize_t count = pread64(fd, data, std::min<size_t>(size, 65536), off64_t(offset));
                if (count < 0 && errno == EINTR) continue;
                require(count > 0, "Truncated APK data."); data += count; size -= size_t(count); offset += uint64_t(count);
            }
        }
    };
    static Bytes readAt(ArchiveFile&f,uint64_t off,size_t n) {
        Bytes b(n);
        f.read(off,b.data(),n);
        return b;
    }
    Archive::Archive(std::string path):path_(std::move(path)) {
        ArchiveFile f(path_);
        auto end=lseek64(f.fd,0,SEEK_END);
        require(end>=22,"Invalid APK ZIP.");
        fileSize=uint64_t(end);
        auto size=size_t(std::min<uint64_t>(fileSize,65557));
        auto tail=readAt(f,fileSize-size,size);
        size_t e=tail.size();
        for(size_t p=tail.size()-22;;--p) {
            if(get32(tail,p)==0x06054b50&&p+22+get16(tail,p+20)==tail.size()) {
                e=p;
                break;
            }
            if(p==0)break;
        }
        require(e<tail.size(),"APK ZIP directory is missing.");
        require(get16(tail,e+4)==0&&get16(tail,e+6)==0&&get16(tail,e+8)==get16(tail,e+10),"Multi-volume ZIP is unsupported.");
        auto count=get16(tail,e+10);
        auto cdSize=get32(tail,e+12),cd=get32(tail,e+16);
        require(count<65535&&cd<NONE&&cdSize<NONE&&uint64_t(cd)+cdSize==fileSize-size+e,"ZIP64 APKs are unsupported by this APK format writer.");
        auto directory=readAt(f,cd,cdSize);
        size_t p=0;
        std::set<std::string>names;
        for(uint32_t i=0;i<count;++i) {
            Reader r(directory,p);
            r.need(46);
            require(r.u32()==0x02014b50,"Invalid APK directory entry.");
            r.u16();
            r.u16();
            ZipEntry x;
            x.flags=r.u16();
            x.method=r.u16();
            x.time=r.u16();
            x.date=r.u16();
            x.crc=r.u32();
            x.compressed=r.u32();
            x.size=r.u32();
            auto nl=r.u16(),el=r.u16(),cl=r.u16();
            require(r.u16()==0,"Multi-volume APK entry.");
            r.u16();
            x.external=r.u32();
            x.offset=r.u32();
            auto nb=r.take(nl);
            x.name.assign(nb.begin(),nb.end());
            r.need(size_t(el)+cl);
            p=r.p+el+cl;
            require(!(x.flags&1)&&(x.method==0||x.method==8),"Encrypted/unsupported ZIP entry.");
            require(!x.name.empty()&&x.name[0]!='/'&&x.name.find('\0')==std::string::npos&&x.name.find('\\')==std::string::npos&&x.name!=".."&&x.name.find("../")!=0&&x.name.find("/../")==std::string::npos&&(x.name.size()<3||x.name.substr(x.name.size()-3)!="/..")&&names.insert(x.name).second,"Invalid or duplicate APK filename.");
            require(x.compressed<NONE&&x.size<NONE&&x.offset<NONE,"ZIP64 APK entry.");
            require(x.method!=0||x.size==x.compressed,"Stored ZIP size mismatch.");
            require(uint64_t(x.offset)+30<=cd,"Invalid local ZIP offset.");
            auto local=readAt(f,x.offset,30);
            require(get32(local,0)==0x04034b50&&get16(local,8)==x.method,"Invalid local ZIP header.");
            auto localName=readAt(f,uint64_t(x.offset)+30,get16(local,26));
            require(localName==nb,"Local and central ZIP names disagree.");
            x.dataOffset=uint64_t(x.offset)+30+get16(local,26)+get16(local,28);
            require(x.dataOffset+x.compressed<=cd,"Truncated APK entry.");
            entries.push_back(std::move(x));
        }
        require(p==directory.size(),"Invalid ZIP directory length.");
    }
    const ZipEntry* Archive::find(const std::string&name)const {
        for(const auto&e:entries)if(e.name==name)return &e;
        return nullptr;
    }
    Bytes Archive::extract(const std::string&name)const {
        auto entry=find(name);
        require(entry!=nullptr,"APK entry missing: "+name);
        return extract(*entry);
    }
    void Archive::extractTo(const ZipEntry&e,const std::function<void(const uint8_t*,size_t)>&sink)const {
        ArchiveFile f(path_);
        uint64_t cursor=e.dataOffset;

        uLong crc=crc32(0L,Z_NULL,0);
        std::vector<uint8_t> buffer(65536);
        if(e.method==0) {
            size_t off=0;
            while(off<e.size) {
                auto n=std::min(buffer.size(),size_t(e.size)-off);
                f.read(cursor,buffer.data(),n); cursor+=n;
                crc=crc32(crc,buffer.data(),uInt(n));
                sink(buffer.data(),n);
                off+=n;
            }
        }
        else {
            z_stream z{};
            require(inflateInit2(&z,-MAX_WBITS)==Z_OK,"Cannot initialize ZIP decompressor.");
            struct End {
                z_stream*z;
                ~End() {
                    inflateEnd(z);
                }
            }
            end {
                &z
            };
            uint64_t left=e.compressed;
            size_t written=0;
            int status=Z_OK;
            std::vector<uint8_t> decoded(65536);
            while(status!=Z_STREAM_END) {
                if(!z.avail_in&&left) {
                    auto n=size_t(std::min<uint64_t>(left,buffer.size()));
                    f.read(cursor,buffer.data(),n); cursor+=n;
                    z.next_in=buffer.data();
                    z.avail_in=uInt(n);
                    left-=n;
                }
                z.next_out=decoded.data();
                z.avail_out=uInt(decoded.size());
                auto before=z.avail_in;
                status=inflate(&z,Z_NO_FLUSH);
                require(status==Z_OK||status==Z_STREAM_END,"Invalid compressed APK entry.");
                auto n=decoded.size()-z.avail_out;
                require(n<=size_t(e.size)-written,"APK entry expands beyond its declared size.");
                sink(decoded.data(),n);
                crc=crc32(crc,decoded.data(),uInt(n));
                written+=n;
                require(status==Z_STREAM_END||n||z.avail_in!=before||left,"Truncated deflate stream.");
            }
            require(written==e.size&&left==0&&z.avail_in==0,"APK decompressed size mismatch.");
        }
        require(uint32_t(crc)==e.crc,"APK entry CRC mismatch: "+e.name);
    }
    Bytes Archive::extract(const ZipEntry&e)const {
        Bytes out; out.reserve(e.size);
        extractTo(e,[&](const uint8_t* data,size_t size){ out.insert(out.end(),data,data+size); });
        return out;
    }
    static Bytes deflateBytes(const Bytes&b) {
        z_stream z{};
        require(deflateInit2(&z,3,Z_DEFLATED,-MAX_WBITS,8,Z_DEFAULT_STRATEGY)==Z_OK,"Cannot initialize ZIP compressor.");
        struct End {
            z_stream*z;
            ~End() {
                deflateEnd(z);
            }
        }
        end {
            &z
        };
        Bytes out;
        std::vector<uint8_t> buffer(65536);
        size_t off=0;
        int status=Z_OK;
        while(status!=Z_STREAM_END) {
            if(!z.avail_in&&off<b.size()) {
                auto n=std::min<size_t>(b.size()-off,1024*1024);
                z.next_in=const_cast<Bytef*>(b.data()+off);
                z.avail_in=uInt(n);
                off+=n;
            }
            z.next_out=buffer.data();
            z.avail_out=uInt(buffer.size());
            status=deflate(&z,off==b.size()?Z_FINISH:Z_NO_FLUSH);
            require(status==Z_OK||status==Z_STREAM_END,"ZIP compression failed.");
            out.insert(out.end(),buffer.begin(),buffer.begin()+buffer.size()-z.avail_out);
        }
        return out;
    }
    static uint32_t crcOf(const Bytes&b) {
        uLong c=crc32(0L,Z_NULL,0);
        for(size_t p=0;p<b.size();) {
            auto n=std::min<size_t>(1024*1024,b.size()-p);
            c=crc32(c,b.data()+p,uInt(n));
            p+=n;
        }
        return uint32_t(c);
    }
    bool signatureEntry(const std::string&name) {
        std::string n=name;
        for(auto&c:n)c=char(std::toupper(static_cast<unsigned char>(c)));
        if(n.rfind("META-INF/",0)!=0)return false;
        auto tail=n.substr(9);
        if(tail.find('/')!=std::string::npos)return false;
        if(tail=="MANIFEST.MF"||tail.rfind("SIG-",0)==0)return true;
        for(const auto*ext: {
            ".SF",".RSA",".DSA",".EC"
        })if(tail.size()>=std::strlen(ext)&&tail.substr(tail.size()-std::strlen(ext))==ext)return true;
        return false;
    }
    bool dexEntry(const std::string&name) {
        if(name=="classes.dex")return true;
        if(name.size()<12||name.rfind("classes",0)!=0||name.substr(name.size()-4)!=".dex")return false;
        auto n=name.substr(7,name.size()-11);
        if(n.empty()||n[0]=='0'||n=="1")return false;
        return std::all_of(n.begin(),n.end(),[](char c) {
            return c>='0'&&c<='9';
        });
    }
    void writeArchive(const Archive&input,const std::string&output,const std::map<std::string,Replacement>&replacements,const std::set<std::string>&remove,const std::function<void()>&cancel) {
        require(output!=input.path(),"Output must not overwrite the input APK.");
        std::ofstream out(output,std::ios::binary|std::ios::trunc);
        require(bool(out),"Cannot create APK output.");
        std::ifstream in(input.path(),std::ios::binary);
        require(bool(in),"Cannot reopen APK.");
        uint64_t offset=0;
        std::vector<Bytes>central;
        std::vector<char> buffer(1024*1024);
        auto emit=[&](const Bytes&b) {
            out.write(reinterpret_cast<const char*>(b.data()),std::streamsize(b.size()));
            offset+=b.size();
            require(bool(out),"Cannot write APK; check free space.");
        };
        auto addCentral=[&](const ZipEntry&e,uint16_t flags,uint32_t start) {
            Writer c;
            c.u32(0x02014b50).u16(20).u16(20).u16(flags).u16(e.method).u16(e.time).u16(e.date).u32(e.crc).u32(e.compressed).u32(e.size).u16(narrow(ascii(e.name).size())).u16(0).u16(0).u16(0).u16(0).u32(e.external).u32(start).bytes(ascii(e.name));
            central.push_back(std::move(c.b));
        };
        auto writeEntry=[&](ZipEntry e,const Bytes*data,uint64_t&dataStart) {
            if(cancel)cancel();
            auto name=ascii(e.name);
            require(name.size()<=65535&&e.size<NONE&&e.compressed<NONE,"APK entry exceeds ZIP format.");
            uint32_t align=e.method==0?(e.name.size()>=3&&e.name.substr(e.name.size()-3)==".so"?16384u:4u):1u;
            Writer extra;
            if(align>1) {
                uint32_t n=uint32_t((align-(offset+30+name.size()+4)%align)%align);
                extra.u16(0xffff).u16(n);
                extra.b.insert(extra.b.end(),n,0);
            }
            auto start=narrow(offset);
            require(offset+30+name.size()+extra.b.size()+e.compressed<NONE,"APK requires ZIP64 offsets.");
            Writer h;
            auto flags=uint16_t(e.flags&0x800);
            h.u32(0x04034b50).u16(20).u16(flags).u16(e.method).u16(e.time).u16(e.date).u32(e.crc).u32(e.compressed).u32(e.size).u16(narrow(name.size())).u16(extra.size()).bytes(name).bytes(extra.b);
            emit(h.b);
            dataStart=offset;
            if(data)emit(*data);
            else {
                in.clear();
                in.seekg(std::streamoff(e.dataOffset));
                uint64_t left=e.compressed;
                while(left) {
                    if(cancel)cancel();
                    auto n=size_t(std::min<uint64_t>(left,buffer.size()));
                    in.read(buffer.data(),std::streamsize(n));
                    require(bool(in),"Cannot copy APK entry.");
                    out.write(buffer.data(),std::streamsize(n));
                    require(bool(out),"Cannot write APK; check free space.");
                    offset+=n;
                    left-=n;
                }
            }
            addCentral(e,flags,start);
        };
        uint64_t sharedBase=0,unused=0;
        bool shared=false;
        for(const auto&p:replacements)if(p.second.shareWithSource) {
            require(!shared,"Only one APK entry can share the source data.");
            ZipEntry e;
            e.name=p.first;
            e.flags=0x800;
            e.method=p.second.store?0:8;
            require(e.method==0,"Shared APK source must be stored uncompressed.");
            e.size=narrow(p.second.data.size());
            e.crc=crcOf(p.second.data);
            e.compressed=e.size;
            writeEntry(e,&p.second.data,sharedBase);
            shared=true;
        }
        try {
            for(const auto&e:input.entries)if(!remove.count(e.name)&&!signatureEntry(e.name)&&!replacements.count(e.name)&&e.name.back()!='/') {
                if(shared) {
                    require(uint64_t(sharedBase)+e.offset<NONE,"APK requires ZIP64 offsets.");
                    addCentral(e,uint16_t(e.flags&0x800),narrow(uint64_t(sharedBase)+e.offset));
                }
                else writeEntry(e,nullptr,unused);
            }
            for(const auto&p:replacements)if(!p.second.shareWithSource) {
                ZipEntry e;
                e.name=p.first;
                e.flags=0x800;
                e.method=p.second.store?0:8;
                e.size=narrow(p.second.data.size());
                e.crc=crcOf(p.second.data);
                Bytes packed=p.second.store?Bytes{}:deflateBytes(p.second.data);
                const auto&data=p.second.store?p.second.data:packed;
                e.compressed=narrow(data.size());
                writeEntry(e,&data,unused);
            }
            require(central.size()<65535,"Too many APK entries for ZIP32.");
            auto cd=narrow(offset);
            for(const auto&c:central)emit(c);
            auto size=narrow(offset-cd);
            Writer e;
            e.u32(0x06054b50).u16(0).u16(0).u16(narrow(central.size())).u16(narrow(central.size())).u32(size).u32(cd).u16(0);
            emit(e.b);
            out.close();
            require(bool(out),"Could not finish APK.");
        }
        catch(...) {
            out.close();
            std::remove(output.c_str());
            throw;
        }
    }

}
