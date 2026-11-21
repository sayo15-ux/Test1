#include "dex.hpp"
#include "strings.hpp"

namespace dexpack::payload {
    Bytes stub() {
        dex::Model model;
        dex::Class marker;
        marker.type = u"LbyScKit;";
        marker.super = u"Ljava/lang/Object;";
        marker.flags = 0x11;
        model.classes.push_back(marker);
        auto bytes = dex::write(model);
        require(bytes.size() <= 416, "Shield marker exceeds its container prefix.");
        bytes.resize(416);
        put32(bytes, 104, narrow(bytes.size()-get32(bytes, 108)));
        fixDex(bytes);
        return bytes;
    }
}
