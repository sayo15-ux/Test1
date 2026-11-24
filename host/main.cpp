#include "engine.hpp"
#include <iostream>
int main(int argc,char**argv) {
    try {
        using namespace dexpack;
        require(argc>=3,"Usage: dexpack classes|inspect|roundtrip|v1|v2|shield|signature input [output] [class-list]");
        std::string command=argv[1];
        if(command=="crypto") {
            std::cout<<hex(md5(ascii(argv[2])))<<'\n'<<hex(sha1(reinterpret_cast<const uint8_t*>(argv[2]),std::strlen(argv[2])))<<'\n'<<utf8(encryptString(utf16(argv[2]),u"ScKit"))<<'\n';
            return 0;
        }
        if(command=="roundtrip") {
            require(argc>=4,"Output path required.");
            auto m=dex::read(readFile(argv[2]));
            writeFile(argv[3],dex::write(m));
            return 0;
        }
        if(command=="share") {
            require(argc>=4,"Input and output paths required.");
            Archive input(argv[2]);
            std::map<std::string,Replacement> replacements;
            replacements["assets/fancy/origin.apk"]={readFile(argv[2]),true,true};
            writeArchive(input,argv[3],replacements,{});
            return 0;
        }
        if(command=="patchmethods") {
            require(argc>=5,"Input, class def offset, and output required.");
            auto bytes=readFile(argv[2]);
            patchFinalMethods(bytes,uint32_t(std::stoul(argv[3])),{"attachBaseContext","onCreate"});
            fixDex(bytes);
            writeFile(argv[4],bytes);
            return 0;
        }
        Input input(argv[2]);
        if(command=="inspect") {
            std::cout<<utf8(input.info.packageName)<<'\n'<<utf8(input.info.sharedUserId)<<'\n'<<input.info.minSdk<<'\n'<<input.info.targetSdk<<'\n';
            return 0;
        }
        auto names=classes(input);
        if(command=="classes") {
            for(const auto&s:names)std::cout<<utf8(s)<<'\n';
            return 0;
        }
        require(argc>=4,"Output path required.");
        std::set<Text>selected(names.begin(),names.end());
        if(argc>=5) {
            selected.clear();
            std::ifstream f(argv[4]);
            require(bool(f),"Cannot read class list.");
            std::string line;
            while(std::getline(f,line)) {
                if(!line.empty()&&line.back()=='\r')line.pop_back();
                if(!line.empty())selected.insert(utf16(line));
            }
        }
        int mode=command=="v1"?1:command=="v2"?2:command=="shield"?0:command=="signature"?3:command=="v4"?6:-1;
        auto r=protect(input,argv[3],mode,selected);
        std::cout<<"{\"classes\":"<<r.classes<<",\"literals\":"<<r.literals<<",\"staticFields\":"<<r.staticFields<<",\"uniqueStrings\":"<<r.uniqueStrings<<",\"classTables\":"<<r.classTables<<",\"methodsReframed\":"<<r.methodsReframed<<",\"highRegisterSites\":"<<r.highRegisterSites<<",\"bridgeMethods\":"<<r.bridges<<"}\n";
        return 0;
    }
    catch(const std::exception&e) {
        std::cerr<<e.what()<<'\n';
        return 1;
    }
}
