#pragma once
#include "bytes.hpp"
namespace dexpack {
    struct ManifestInfo {
        Text packageName, sharedUserId, applicationName=u"android.app.Application", factoryName;
        uint32_t minSdk=1,targetSdk=1;
        bool hasApplication=false;
    };
    ManifestInfo inspectManifest(const Bytes& bytes);
    Bytes shieldManifest(const Bytes& bytes);
}
