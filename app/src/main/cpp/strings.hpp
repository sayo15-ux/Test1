#pragma once
#include "dex.hpp"
namespace dexpack {
    struct StringReport {
        uint64_t classes=0,literals=0,staticFields=0,uniqueStrings=0,classTables=0;
        uint64_t methodsReframed=0,highRegisterSites=0,bridges=0,interfacesPreserved=0;
        StringReport& operator+=(const StringReport& other);
    };
    struct StringContext {
        struct Bridge {
            dex::Ref ref;
            Text cipher,password;
        };
        std::string token;
        Text owner, templateOwner;
        dex::Ref decoder;
        int version=0;
        std::map<std::pair<Text,Text>,Text> v1;
        std::map<std::pair<Text,Text>,Bridge> bridges;
        std::map<Text,Text> v2;
        std::function<int64_t()> millis;
        explicit StringContext(std::string token = randomToken());
        void prepare(int version, const std::set<Text>& occupied = {});
    };
    using Progress = std::function<void(const std::string&,int)>;
    struct StringResult {
        Bytes bytes;
        StringReport report;
        bool changed=false;
    };
    StringResult transformStrings(const Bytes& input,int version,const std::set<Text>& selected,StringContext& ctx,const Progress& progress = {});
    dex::Model stringHelper(int version,StringContext& context);
    Bytes stringHelperDex(int version,StringContext& context);
    namespace payload {
        Bytes v1();
        Bytes v2();
        Bytes shell();
        Bytes stub();
        Bytes library(const std::string& abi);
    }
}
