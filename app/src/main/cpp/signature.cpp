#include "signature.hpp"
#include <utility>

namespace dexpack {
    namespace {
        using namespace dex;
        const Text PACKAGE_MANAGER = u"Landroid/content/pm/PackageManager;";
        const Text SIGNATURE = u"Landroid/content/pm/Signature;";
        const Text SIGNING_INFO = u"Landroid/content/pm/SigningInfo;";
        const Text PACKAGE_INFO = u"Landroid/content/pm/PackageInfo;";
        const Text MESSAGE_DIGEST = u"Ljava/security/MessageDigest;";
        const Text X509 = u"Ljava/security/cert/X509Certificate;";
        const Text ARRAYS = u"Ljava/util/Arrays;";

        // GET_SIGNATURES | GET_SIGNING_CERTIFICATES
        constexpr int32_t SIGNATURE_FLAGS = 0x40 | 0x08000000;

        std::optional<int32_t> literal(const Instruction& i) {
            if (i.op == 0x12) {
                int32_t v = int32_t(i.units[0] >> 8);
                return (v & 8) ? v | ~0xf : v;
            }
            if (i.op == 0x13 && i.units.size() >= 2) return int32_t(int16_t(i.units[1]));
            if (i.op == 0x14 && i.units.size() >= 3) return int32_t(uint32_t(i.units[1]) | (uint32_t(i.units[2]) << 16));
            return {};
        }

        bool asksForSignatures(const std::vector<Instruction>& code, size_t at) {
            size_t back = 0;
            for (size_t k = at; k > 0 && back++ < 12; --k) {
                auto value = literal(code[k - 1]);
                if (value && (*value & SIGNATURE_FLAGS)) return true;
                uint8_t op = code[k - 1].op;
                // Stop at a value-producing instruction that is unlikely to be the flags.
                if (op == 0x0c || op == 0x71 || op == 0x6e || op == 0x76 || op == 0x1b) break;
            }
            return false;
        }

        bool strongReference(const Ref& ref, const std::vector<Instruction>& code, size_t at) {
            if (!ref) return false;
            if (ref->kind == Kind::Field) {
                return ref->owner == PACKAGE_INFO
                    && (ref->text == u"signatures" || ref->text == u"signingInfo");
            }
            if (ref->kind != Kind::Method) return false;
            if (ref->owner == SIGNATURE || ref->owner == SIGNING_INFO) return true;
            if (ref->owner == PACKAGE_MANAGER
                && (ref->text == u"getPackageInfo" || ref->text == u"getPackageArchiveInfo")) {
                return asksForSignatures(code, at);
            }
            return false;
        }

        bool supportingReference(const Ref& ref) {
            if (!ref || ref->kind != Kind::Method) return false;
            if (ref->owner == PACKAGE_MANAGER
                && (ref->text == u"getPackageInfo" || ref->text == u"getPackageArchiveInfo")) return true;
            if (ref->owner == MESSAGE_DIGEST && (ref->text == u"getInstance" || ref->text == u"digest")) return true;
            if (ref->owner == ARRAYS && ref->text == u"equals") return true;
            if (ref->owner == X509 && (ref->text == u"getEncoded" || ref->text == u"getPublicKey" || ref->text == u"verify")) return true;
            return false;
        }

        // Replaces a verification method with a small stub that reports success.
        std::pair<std::vector<Instruction>, uint32_t> successStub(const Ref& ref, uint32_t ins) {
            using std::pair;
            using std::vector;
            const Text& result = ref->proto->type;
            vector<Instruction> code;
            uint32_t registers = ins ? ins : 1;
            if (result == u"V") {
                code.push_back(raw({0x0e}));                       // return-void
            } else if (result == u"Z" || result == u"B" || result == u"S"
                    || result == u"I" || result == u"C" || result == u"F") {
                code.push_back(constant(0, result == u"Z" ? 1 : 0));
                code.push_back(raw({0x0f}));                       // return v0
            } else if (result == u"J" || result == u"D") {
                registers = ins > 2 ? ins : 2;
                code.push_back(raw({0x16, 0, 0}));                 // const-wide/16 v0, 0
                code.push_back(raw({0x10}));                       // return-wide v0
            } else {
                code.push_back(raw({0x12, 0}));                    // const/4 v0, null
                code.push_back(raw({0x11}));                       // return-object v0
            }
            return {std::move(code), registers};
        }
    }

    SignatureResult killSignatures(const Bytes& input, const Progress& progress) {
        auto model = dex::read(input);
        SignatureResult result;
        const size_t total = model.classes.size();
        for (size_t n = 0; n < total; ++n) {
            auto& c = model.classes[n];
            bool classChanged = false;
            for (auto* list : {&c.direct, &c.virtuals}) {
                for (auto& m : *list) {
                    if (!m->code) continue;
                    const Text& name = m->ref->text;
                    // Constructors and initializers are kept intact; killing them
                    // would break object creation or static setup of the app.
                    if (name == u"<init>" || name == u"<clinit>") continue;
                    size_t strong = 0, supporting = 0;
                    const auto& code = m->code->instructions;
                    for (size_t i = 0; i < code.size(); ++i) {
                        if (strongReference(code[i].ref, code, i)) ++strong;
                        else if (supportingReference(code[i].ref)) ++supporting;
                    }
                    if (!strong && supporting < 2) continue;
                    auto stub = successStub(m->ref, m->code->ins);
                    m->code = dex::newCode(std::move(stub.first), stub.second, m->code->ins, 1);
                    ++result.report.methods;
                    result.report.sites += strong + supporting;
                    classChanged = true;
                }
            }
            if (classChanged) ++result.report.classes;
            if (progress && (n % 16 == 0 || n + 1 == total)) {
                progress("Killing signatures", int((n + 1) * 100 / total));
            }
        }
        result.changed = result.report.methods != 0;
        result.bytes = result.changed ? dex::write(model) : input;
        validateDex(result.bytes);
        return result;
    }
}
