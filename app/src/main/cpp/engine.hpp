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
    void patchFinalMethods(Bytes& bytes,uint32_t classDefOff,const std::set<std::string>& names);
    StringReport protect(const Input& input,const std::string& output,int mode,const std::set<Text>& selected,const Progress& progress={},std::optional<int64_t> fixedClock={},const SignatureKillV3Options& sigV3={},const SignatureKillV4Options& sigV4={},const Text& signatureDigest={});
}
