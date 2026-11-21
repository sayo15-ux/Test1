#pragma once
#include "bytes.hpp"
namespace dexpack::shield {
    struct Entry { std::string name; uint32_t offset, size; };
    struct Index {
        std::vector<Entry> dex;
        std::string application;
        bool hasApplication = false;
    };
    struct Installed {
        std::vector<std::string> dexPaths;
        std::string optimizedDirectory, application;
    };
    Index inspect(const uint8_t* data, size_t size);
    Installed install(const std::string& apk, const std::string& dataDirectory);
}
