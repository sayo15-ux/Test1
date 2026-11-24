#pragma once
#include "bytes.hpp"
namespace dexpack::fancy {
    Bytes referenceDex();
    Bytes library(const std::string& abi);
    Bytes ownLibrary(const std::string& abi);
}
