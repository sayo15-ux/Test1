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
    Bytes signatureKillerManifest(const Bytes& bytes, const Text& applicationName);
    Bytes signatureKillerManifestV3(const Bytes& bytes, const Text& applicationName, bool earlyProvider, bool debuggable);
    Bytes signatureKillerManifestV4(const Bytes& bytes, const Text& applicationName, const Text& originalApplicationName, const Text& componentFactory, bool debuggable);
}
