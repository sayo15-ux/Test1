#pragma once
#include "archive.hpp"
#include "manifest.hpp"
#include "strings.hpp"
#include "signature.hpp"
namespace dexpack {
    struct Input {
        Archive archive;
        Bytes manifest;
        ManifestInfo info;
        std::vector<std::string> dexNames,abis;
        explicit Input(const std::string&path);
    };
    std::vector<Text> classes(const Input& input);
    StringReport protect(const Input& input,const std::string& output,int mode,const std::set<Text>& selected,const Progress& progress={},std::optional<int64_t> fixedClock={});
}
