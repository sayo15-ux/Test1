#pragma once
#include "archive.hpp"
#include "manifest.hpp"
#include "strings.hpp"
#include <set>
namespace dexpack {
    struct SignatureReport {
        uint64_t classes = 0, methods = 0, sites = 0;
    };
    struct SignatureKillV3Options {
        bool pmProxy = true;
        bool earlyProvider = true;
        bool patchSigningInfo = true;
        bool replaceApkPath = true;
        bool patchApplicationInfo = true;
        bool basicsToSign = false;
        bool debuggable = false;
        std::string fileRedirection = "default";
        uint32_t flags = 0;
    };
    struct SignatureKillV4Options {
        bool pmProxy = true;
        bool patchSigningInfo = true;
        bool replaceApkPath = false;
        bool patchApplicationInfo = false;
        bool embedOriginalApk = false;
        bool delegateOriginalApplication = true;
        bool debuggable = false;
        uint32_t flags = 0;
    };
    struct SignatureOptions {
        Text className, factoryName, applicationName, packageName, originalApkAsset;
        std::set<Text> classes;
        SignatureKillV3Options v3;
        SignatureKillV4Options v4;
    };
    struct SignatureResult {
        Bytes bytes;
        SignatureReport report;
        bool changed = false;
    };
    SignatureResult killSignatures(const Archive& apk, const SignatureOptions& options, const Progress& progress = {});
    SignatureResult killSignaturesV2(const Archive& apk, const SignatureOptions& options, const Progress& progress = {});
    SignatureResult killSignaturesV3(const Archive& apk, const SignatureOptions& options, const Progress& progress = {});
    SignatureResult killSignaturesV4(const Archive& apk, const SignatureOptions& options, const Progress& progress = {});
}
