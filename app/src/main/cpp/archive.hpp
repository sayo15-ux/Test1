#pragma once
#include "bytes.hpp"
namespace dexpack {
    struct ZipEntry {
        std::string name;
        uint16_t flags=0,method=0,time=0,date=0;
        uint32_t crc=0,size=0,compressed=0,external=0,offset=0;
        uint64_t dataOffset=0;
    };
    class Archive {
        std::string path_;
        public:     std::vector<ZipEntry> entries;
        uint64_t fileSize=0;
        explicit Archive(std::string path);
        const std::string& path()const {
            return path_;
        }
        const ZipEntry* find(const std::string& name)const;
        Bytes extract(const ZipEntry& entry)const;
        void extractTo(const ZipEntry& entry,const std::function<void(const uint8_t*,size_t)>& sink)const;
        Bytes extract(const std::string& name)const;
    };
    struct Replacement {
        Bytes data;
        bool store=false;
    };
    void writeArchive(const Archive& input,const std::string& output,const std::map<std::string,Replacement>&replacements,const std::set<std::string>&remove,const std::function<void()>&cancel={});
    bool signatureEntry(const std::string& name);
    bool dexEntry(const std::string& name);
}
