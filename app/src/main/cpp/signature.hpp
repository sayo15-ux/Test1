#pragma once
#include "strings.hpp"
namespace dexpack {
    struct SignatureReport {
        uint64_t classes = 0, methods = 0, sites = 0;
    };
    struct SignatureResult {
        Bytes bytes;
        SignatureReport report;
        bool changed = false;
    };
    SignatureResult killSignatures(const Bytes& input, const Progress& progress = {});
}
