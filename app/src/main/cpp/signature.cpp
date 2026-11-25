#include "signature.hpp"
#include <algorithm>
#include <cctype>
#include <optional>
#include <utility>

namespace dexpack {
    namespace {
        using namespace dex;
        const Text CREATOR = u"Landroid/os/Parcelable$Creator;";
        const Text SIGNATURE = u"Landroid/content/pm/Signature;";
        const Text SIGNATURE_ARRAY = u"[Landroid/content/pm/Signature;";
        const Text PACKAGE_INFO = u"Landroid/content/pm/PackageInfo;";
        const Text APPLICATION_INFO = u"Landroid/content/pm/ApplicationInfo;";
        const Text OBJECT = u"Ljava/lang/Object;";

        struct Der {
            uint8_t tag = 0;
            size_t begin = 0, body = 0, end = 0;
        };

        std::optional<Der> der(const Bytes& bytes, size_t begin, size_t limit) {
            if (begin + 2 > limit) return {};
            size_t p = begin;
            uint8_t tag = bytes[p++];
            if ((tag & 0x1f) == 0x1f || p >= limit) return {};
            size_t length = bytes[p++];
            if (length & 0x80) {
                size_t n = length & 0x7f;
                if (!n || n > 4 || p + n > limit) return {};
                length = 0;
                for (size_t i = 0; i < n; ++i) length = (length << 8) | bytes[p++];
            }
            if (p + length > limit) return {};
            return Der{tag, begin, p, p + length};
        }

        std::optional<Bytes> certificate(const Bytes& block) {
            auto root = der(block, 0, block.size());
            if (!root || root->tag != 0x30) return {};
            size_t p = root->body;
            while (p < root->end) {
                auto child = der(block, p, root->end);
                if (!child) break;
                if (child->tag == 0xa0) {
                    auto signedData = der(block, child->body, child->end);
                    if (signedData && signedData->tag == 0x30) {
                        size_t q = signedData->body;
                        while (q < signedData->end) {
                            auto field = der(block, q, signedData->end);
                            if (!field) break;
                            if (field->tag == 0xa0) {
                                size_t r = field->body;
                                while (r < field->end) {
                                    auto item = der(block, r, field->end);
                                    if (!item) break;
                                    if (item->tag == 0x30 && item->end - item->begin > 64)
                                        return slice(block, item->begin, item->end - item->begin);
                                    r = item->end;
                                }
                            }
                            q = field->end;
                        }
                    }
                }
                p = child->end;
            }
            size_t scan = 0;
            while (scan < block.size()) {
                auto item = der(block, scan, block.size());
                if (!item) break;
                if (item->tag == 0x30 && item->end - item->begin > 64) {
                    auto first = der(block, item->body, item->end);
                    if (first && first->tag == 0x02)
                        return slice(block, item->begin, item->end - item->begin);
                }
                scan = item->end;
            }
            return {};
        }

        uint16_t little16(const Bytes& bytes, size_t offset) {
            require(offset + 2 <= bytes.size(), "Truncated APK signature block.");
            return uint16_t(bytes[offset]) | uint16_t(bytes[offset + 1]) << 8;
        }

        uint32_t little32(const Bytes& bytes, size_t offset) {
            require(offset + 4 <= bytes.size(), "Truncated APK signature block.");
            return uint32_t(bytes[offset]) | uint32_t(bytes[offset + 1]) << 8
                    | uint32_t(bytes[offset + 2]) << 16 | uint32_t(bytes[offset + 3]) << 24;
        }

        uint64_t little64(const Bytes& bytes, size_t offset) {
            require(offset + 8 <= bytes.size(), "Truncated APK signature block.");
            uint64_t value = 0;
            for (size_t i = 0; i < 8; ++i) value |= uint64_t(bytes[offset + i]) << (8 * i);
            return value;
        }

        Bytes signingBlockCertificate(const std::string& path) {
            Bytes apk = readFile(path);
            static const char magic[] = "APK Sig Block 42";
            size_t eocd = apk.size();
            bool found = false;
            while (eocd >= 22) {
                if (little32(apk, eocd - 22) == 0x06054b50
                        && eocd - 22 + 22 + little16(apk, eocd - 2) == apk.size()) {
                    eocd -= 22;
                    found = true;
                    break;
                }
                --eocd;
            }
            require(found, "APK v2 signature block has no end record.");
            uint64_t central = little32(apk, eocd + 16);
            require(central >= 24 && central + 22 <= apk.size(), "Invalid APK central directory.");
            size_t trailer = size_t(central - 24);
            uint64_t blockSize = little64(apk, trailer);
            require(blockSize <= trailer && std::memcmp(apk.data() + central - 16, magic, 16) == 0,
                    "Invalid APK signature block.");
            size_t start = trailer;
            while (start >= 8 && little64(apk, start - 8) != blockSize) --start;
            require(start >= 8, "APK signature block size mismatch.");
            start -= 8;
            size_t end = trailer;
            for (size_t p = start + 8; p < end;) {
                require(end - p >= 8, "Truncated APK signature block pair.");
                uint64_t length = little64(apk, p);
                require(length >= 4 && length <= end - p - 8, "Invalid APK signature block pair.");
                if (little32(apk, p + 8) == 0x7109871a) {
                    size_t value = p + 12, limit = size_t(p + 8 + length);
                    while (value < limit) {
                        uint32_t signerSize = little32(apk, value);
                        value += 4;
                        require(signerSize <= limit - value, "Invalid APK v2 signer.");
                        size_t signer = value, signerEnd = signer + signerSize;
                        uint32_t signedSize = little32(apk, signer);
                        signer += 4;
                        require(signedSize <= signerEnd - signer, "Invalid APK v2 signed data.");
                        size_t signedEnd = signer + signedSize;
                        uint32_t digests = little32(apk, signer);
                        signer += 4 + uint64_t(digests);
                        require(signer <= signedEnd, "Invalid APK v2 digests.");
                        uint32_t certificates = little32(apk, signer);
                        signer += 4;
                        require(certificates <= signedEnd - signer, "Invalid APK v2 certificates.");
                        size_t certificatesEnd = signer + certificates;
                        uint32_t certificate = little32(apk, signer);
                        signer += 4;
                        require(certificate <= certificatesEnd - signer, "Invalid APK v2 certificate.");
                        return slice(apk, signer, certificate);
                    }
                    break;
                }
                p += size_t(8 + length);
            }
            require(false, "No APK v2 certificate was found.");
            return {};
        }

        Bytes originalCertificate(const Archive& apk) {
            for (const auto& entry : apk.entries) {
                std::string name = entry.name;
                for (auto& c : name) c = char(std::toupper(static_cast<unsigned char>(c)));
                if (name.rfind("META-INF/", 0) != 0 || name.find('/', 9) != std::string::npos) continue;
                bool signature = false;
                for (const auto* extension : {".RSA", ".DSA", ".EC"})
                    if (name.size() >= std::char_traits<char>::length(extension)
                            && name.compare(name.size() - std::char_traits<char>::length(extension),
                                    std::char_traits<char>::length(extension), extension) == 0)
                        signature = true;
                if (!signature) continue;
                if (auto found = certificate(apk.extract(entry))) return *found;
            }
            return signingBlockCertificate(apk.path());
        }

        std::string base64(const Bytes& bytes) {
            static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            out.reserve((bytes.size() + 2) / 3 * 4);
            for (size_t i = 0; i < bytes.size(); i += 3) {
                uint32_t word = uint32_t(bytes[i]) << 16;
                if (i + 1 < bytes.size()) word |= uint32_t(bytes[i + 1]) << 8;
                if (i + 2 < bytes.size()) word |= bytes[i + 2];
                out += alphabet[(word >> 18) & 63];
                out += alphabet[(word >> 12) & 63];
                out += i + 1 < bytes.size() ? alphabet[(word >> 6) & 63] : '=';
                out += i + 2 < bytes.size() ? alphabet[word & 63] : '=';
            }
            return out;
        }

        Text descriptor(const Text& name) {
            if (!name.empty() && name[0] == u'L') return name;
            Text result;
            for (auto c : name) result += c == u'.' ? u'/' : c;
            return u"L" + result + u";";
        }

        Instruction field21(uint8_t op, uint16_t reg, const Ref& ref) {
            return raw({uint16_t(op | (reg << 8)), 0}, ref);
        }
        Instruction field22(uint8_t op, uint16_t value, uint16_t object, const Ref& ref) {
            return raw({uint16_t(op | (value << 8) | (object << 12)), 0}, ref);
        }
        Instruction typeOp(uint8_t op, uint16_t reg, const Text& type) {
            return field21(op, reg, textRef(Kind::Type, type));
        }
        Instruction arrayOp(uint8_t op, uint16_t dest, uint16_t size, const Text& type) {
            return raw({uint16_t(op | (dest << 8) | (size << 12)), 0}, textRef(Kind::Type, type));
        }
        Instruction three(uint8_t op, uint16_t a, uint16_t b, uint16_t c) {
            return raw({uint16_t(op | (a << 8)), uint16_t((c << 8) | b)});
        }
        Instruction moveObject(uint16_t dst, uint16_t src) {
            return raw({uint16_t(0x07 | (dst << 8) | (src << 12))});
        }
        Instruction moveInt(uint16_t dst, uint16_t src) {
            return raw({uint16_t(0x01 | (dst << 8) | (src << 12))});
        }
        Instruction resultObject(uint16_t reg) {
            return raw({uint16_t(0x0c | (reg << 8))});
        }
        Instruction resultInt(uint16_t reg) {
            return raw({uint16_t(0x0a | (reg << 8))});
        }
        Instruction call(const Ref& ref, uint16_t base, uint8_t count, uint8_t op) {
            if (op >= 0x74 && op <= 0x78) {
                return raw({uint16_t(op | (uint16_t(count) << 8)), 0, base}, ref);
            }
            uint16_t w2 = 0;
            for (uint8_t i = 0; i < count && i < 4; ++i) w2 |= uint16_t((base + i) & 0xf) << (4 * i);
            uint8_t g = (count >= 5) ? uint8_t((base + 4) & 0xf) : 0;
            return raw({uint16_t(op | (uint16_t(g) << 8) | (uint16_t(count) << 12)), 0, w2}, ref);
        }

        struct Builder {
            std::vector<Instruction> instructions;
            Instruction& add(const Instruction& instruction) {
                auto copy = instruction;
                copy.oldPc = int64_t(instructions.size());
                instructions.push_back(std::move(copy));
                return instructions.back();
            }
            void branch(uint8_t op, uint16_t reg, uint32_t target) {
                auto& instruction = add(raw({uint16_t(op | (reg << 8)), 0}));
                instruction.target = target;
            }
            std::shared_ptr<Code> build(uint32_t registers, uint32_t ins, uint32_t outs,
                    std::optional<uint32_t> handler = {}) {
                auto code = newCode(instructions, registers, ins, outs);
                code->oldSize = uint32_t(instructions.size());
                if (handler) {
                    auto h = std::make_shared<Handler>();
                    h->catchAll = *handler;
                    code->tries.push_back({0, uint32_t(*handler), h});
                }
                return code;
            }
        };
    }

    SignatureResult killSignatures(const Archive& apk, const SignatureOptions& options, const Progress& progress) {
        using namespace dex;
        if (progress) progress("Reading original signature", 15);
        Bytes cert = originalCertificate(apk);
        const Text helper = options.className;
        require(!options.classes.count(helper), "Signature killer class collision.");

        if (progress) progress("Building signature helper", 30);
        const Text STRING=u"Ljava/lang/String;", OBJECT=u"Ljava/lang/Object;", CLASS=u"Ljava/lang/Class;";
        const Text PM=u"Landroid/content/pm/PackageManager;", PI=u"Landroid/content/pm/PackageInfo;";
        const Text SIG=u"Landroid/content/pm/Signature;", SIG_ARR=u"[Landroid/content/pm/Signature;";
        const Text SI=u"Landroid/content/pm/SigningInfo;", FIELD=u"Ljava/lang/reflect/Field;";
        Ref certField=field(helper,u"certificate",u"[B");
        Ref base64Decode=method(u"Landroid/util/Base64;",u"decode",u"[B",{STRING,u"I"});
        Ref signatureInit=method(SIG,u"<init>",u"V",{u"[B"});
        Ref arrayNewInstance=method(u"Ljava/lang/reflect/Array;",u"newInstance",OBJECT,{CLASS,u"I"});
        Ref objectClass=method(OBJECT,u"getClass",CLASS);
        Ref getDeclaredField=method(CLASS,u"getDeclaredField",FIELD,{STRING});
        Ref setAccessible=method(FIELD,u"setAccessible",u"V",{u"Z"});
        Ref fieldSet=method(FIELD,u"set",u"V",{OBJECT,OBJECT});
        Ref signaturesField=field(PI,u"signatures",SIG_ARR);
        Ref signingInfoField=field(PI,u"signingInfo",SI);
        Ref pkgNameField=field(PI,u"packageName",STRING);
        Ref stringEquals=method(STRING,u"equals",u"Z",{OBJECT});
        Ref fake=method(helper,u"$fakeSignatures",SIG_ARR);
        Ref patchSigning=method(helper,u"$patchSigningInfo",u"V",{OBJECT,SIG_ARR});
        Ref patchPkg=method(helper,u"$patchPackageInfo",PI,{PI,STRING});
        Ref hookGetPkg=method(helper,u"$getPackageInfo",PI,{PM,STRING,u"I"});
        Ref hookGetPkgVer=method(helper,u"$getPackageInfo",PI,{PM,STRING,u"Landroid/content/pm/PackageManager$PackageInfoFlags;"});
        Ref hookGetArchive=method(helper,u"$getPackageArchiveInfo",PI,{PM,STRING,u"I"});

        dex::Class app;
        app.type=helper; app.super=OBJECT; app.flags=0x1;
        dex::Field certStore; certStore.ref=certField; certStore.flags=0xa; app.staticFields.push_back(certStore);

        Builder clinit;
        clinit.add(string(0,utf16(base64(cert))));
        clinit.add(constant(1,0));
        clinit.add(call(base64Decode,0,2,0x77)); clinit.add(resultObject(0));
        clinit.add(field21(0x69,0,certField));
        clinit.add(raw({0x0e}));
        app.direct.push_back(newMethod(method(helper,u"<clinit>",u"V"),0x8,clinit.build(2,0,3)));

        Builder initB;
        initB.add(call(method(OBJECT,u"<init>",u"V"),0,1,0x76));
        initB.add(raw({0x0e}));
        app.direct.push_back(newMethod(method(helper,u"<init>",u"V"),0x10001,initB.build(1,1,1)));

        // $fakeSignatures(): Signature[]
        Builder fakeB;
        fakeB.add(field21(0x62,0,certField));
        fakeB.add(constant(3,1));
        fakeB.add(typeOp(0x1c,2,SIG));
        fakeB.add(call(arrayNewInstance,2,2,0x77)); fakeB.add(resultObject(2));
        fakeB.add(typeOp(0x1f,2,SIG_ARR));
        fakeB.add(typeOp(0x22,3,SIG));
        fakeB.add(moveObject(4,0));
        fakeB.add(call(signatureInit,3,2,0x76));
        fakeB.add(constant(4,0));
        fakeB.add(three(0x4d,3,2,4));
        fakeB.add(raw({uint16_t(0x11|(2<<8)),0}));
        app.direct.push_back(newMethod(fake,0x9,fakeB.build(5,0,3)));

        // $patchSigningInfo(Object, Signature[]) - void
        Builder ps;
        // regs=6, ins=2 => p0=v4, p1=v5
        // v0=obj, v1=sigs, v2=class, v3=field
        ps.add(moveObject(0,4)); // obj
        ps.add(moveObject(1,5)); // sigs
        // mApkContentsSigners
        ps.add(moveObject(2,0));
        ps.add(call(objectClass,2,1,0x74)); ps.add(resultObject(2));
        ps.add(string(3,u"mApkContentsSigners"));
        ps.add(call(getDeclaredField,2,2,0x74)); ps.add(resultObject(3));
        ps.add(constant(2,1));
        ps.add(moveObject(4,3)); ps.add(moveInt(5,2));
        ps.add(call(setAccessible,4,2,0x74));
        ps.add(moveObject(2,3)); ps.add(moveObject(3,0)); ps.add(moveObject(4,1));
        ps.add(call(fieldSet,2,3,0x74));
        // mSigningCertificateHistory
        ps.add(moveObject(2,0));
        ps.add(call(objectClass,2,1,0x74)); ps.add(resultObject(2));
        ps.add(string(3,u"mSigningCertificateHistory"));
        ps.add(call(getDeclaredField,2,2,0x74)); ps.add(resultObject(3));
        ps.add(constant(2,1));
        ps.add(moveObject(4,3)); ps.add(moveInt(5,2));
        ps.add(call(setAccessible,4,2,0x74));
        ps.add(moveObject(2,3)); ps.add(moveObject(3,0)); ps.add(moveObject(4,1));
        ps.add(call(fieldSet,2,3,0x74));
        ps.add(raw({0x0e}));
        uint32_t psH=uint32_t(ps.instructions.size());
        ps.add(raw({uint16_t(0x0d|(0<<8))})); ps.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchSigning,0x9,ps.build(6,2,3,psH)));

        // $patchPackageInfo(PackageInfo pi, String targetPkg): PackageInfo
        Builder pp;
        // regs=5, ins=2 => p0=v3, p1=v4
        pp.add(moveObject(0,3));
        uint32_t bNull=uint32_t(pp.instructions.size()); pp.branch(0x38,0,0);
        pp.add(moveObject(1,4));
        uint32_t bDo=uint32_t(pp.instructions.size()); pp.branch(0x38,1,0);
        pp.add(field22(0x54,0,3,pkgNameField));
        pp.add(moveObject(1,4));
        pp.add(call(stringEquals,0,2,0x74)); pp.add(resultInt(0));
        uint32_t bNe=uint32_t(pp.instructions.size()); pp.branch(0x38,0,0);
        uint32_t doPatch=uint32_t(pp.instructions.size());
        pp.add(call(fake,0,0,0x77)); pp.add(resultObject(0));
        pp.add(field22(0x5b,0,3,signaturesField));
        pp.add(field22(0x54,0,3,signingInfoField));
        uint32_t bNoSi=uint32_t(pp.instructions.size()); pp.branch(0x38,0,0);
        pp.add(call(fake,0,0,0x77)); pp.add(resultObject(1));
        pp.add(moveObject(2,1));
        pp.add(moveObject(1,0));
        pp.add(call(patchSigning,1,2,0x77));
        uint32_t noSi=uint32_t(pp.instructions.size());
        uint32_t ret=uint32_t(pp.instructions.size());
        pp.add(raw({uint16_t(0x11|(3<<8)),0}));
        pp.instructions[bNull].target=ret;
        pp.instructions[bDo].target=doPatch;
        pp.instructions[bNe].target=ret;
        pp.instructions[bNoSi].target=noSi;
        app.direct.push_back(newMethod(patchPkg,0x9,pp.build(5,2,3)));

        auto makeGetPkg=[&](const Ref& hookRef,const Text& flagsType,bool flagsIsObject){
            Builder b;
            // regs=7, ins=3 => p0=v4,p1=v5,p2=v6
            b.add(moveObject(0,4)); b.add(moveObject(1,5));
            b.add(flagsIsObject ? moveObject(2,6) : moveInt(2,6));
            Instruction inv; inv.op=0x6e; inv.ref=method(PM,u"getPackageInfo",PI,{STRING,flagsType});
            inv.units={uint16_t(0x6e|(3<<12)),0,uint16_t(0|(1<<4)|(2<<8))}; inv.oldPc=int64_t(b.instructions.size()); b.instructions.push_back(inv);
            b.add(raw({uint16_t(0x0c|(0<<8))}));
            b.add(moveObject(1,5));
            b.add(call(patchPkg,0,2,0x77)); b.add(resultObject(0));
            b.add(raw({uint16_t(0x11|(0<<8)),0}));
            uint32_t h=uint32_t(b.instructions.size());
            b.add(raw({uint16_t(0x0d|(0<<8))})); b.add(constant(0,0)); b.add(raw({uint16_t(0x11|(0<<8)),0}));
            app.direct.push_back(newMethod(hookRef,0x9,b.build(7,3,3,h)));
        };
        makeGetPkg(hookGetPkg,u"I",false);
        makeGetPkg(hookGetPkgVer,u"Landroid/content/pm/PackageManager$PackageInfoFlags;",true);

        {
            Builder b;
            // regs=7, ins=3 => p0=v4,p1=v5,p2=v6
            b.add(moveObject(0,4)); b.add(moveObject(1,5)); b.add(moveInt(2,6));
            Instruction inv; inv.op=0x6e; inv.ref=method(PM,u"getPackageArchiveInfo",PI,{STRING,u"I"});
            inv.units={uint16_t(0x6e|(3<<12)),0,uint16_t(0|(1<<4)|(2<<8))}; inv.oldPc=int64_t(b.instructions.size()); b.instructions.push_back(inv);
            b.add(raw({uint16_t(0x0c|(0<<8))}));
            b.add(constant(1,0));
            b.add(call(patchPkg,0,2,0x77)); b.add(resultObject(0));
            b.add(raw({uint16_t(0x11|(0<<8)),0}));
            uint32_t h=uint32_t(b.instructions.size());
            b.add(raw({uint16_t(0x0d|(0<<8))})); b.add(constant(0,0)); b.add(raw({uint16_t(0x11|(0<<8)),0}));
            app.direct.push_back(newMethod(hookGetArchive,0x9,b.build(7,3,3,h)));
        }

        SignatureResult result;
        dex::Model m; m.classes.push_back(app);
        result.bytes = dex::write(m);
        validateDex(result.bytes);
        result.report.classes = 1;
        result.report.methods = 8;
        result.report.sites = cert.size();
        result.changed = true;
        return result;
    }

    SignatureResult killSignaturesV2(const Archive& apk, const SignatureOptions& options, const Progress& progress) {
        using namespace dex;
        if (progress) progress("Reading original signature", 20);
        Bytes cert = originalCertificate(apk);
        const Text proxy = options.className;
        const Text handler = proxy.substr(0, proxy.size() - 1) + u"$PmsHookBinderInvocationHandler;";
        require(!options.classes.count(proxy) && !options.classes.count(handler),
                "Signature killer v2 class collision.");
        require(!options.originalApkAsset.empty(), "Signature killer v2 needs an original APK asset.");

        if (progress) progress("Building Binder proxy", 40);
        const Text OBJECT_CLASS = u"Ljava/lang/Class;";
        const Text STRING = u"Ljava/lang/String;";
        const Text CONTEXT = u"Landroid/content/Context;";
        const Text LOADER = u"Ljava/lang/ClassLoader;";
        const Text METHOD = u"Ljava/lang/reflect/Method;";
        const Text FIELD = u"Ljava/lang/reflect/Field;";
        const Text HANDLER_INTERFACE = u"Ljava/lang/reflect/InvocationHandler;";

        Ref certField = field(proxy, u"certificate", u"[B");
        Ref originalField = field(proxy, u"original", OBJECT);
        Ref apkPathField = field(proxy, u"originalApkPath", STRING);
        Ref signaturesField = field(PACKAGE_INFO, u"signatures", SIGNATURE_ARRAY);
        Ref signingInfoField = field(PACKAGE_INFO, u"signingInfo", u"Landroid/content/pm/SigningInfo;");
        Ref applicationInfoField = field(PACKAGE_INFO, u"applicationInfo", APPLICATION_INFO);
        Ref sourceDirField = field(APPLICATION_INFO, u"sourceDir", STRING);
        Ref publicSourceDirField = field(APPLICATION_INFO, u"publicSourceDir", STRING);
        Ref splitSourceDirsField = field(APPLICATION_INFO, u"splitSourceDirs", u"[Ljava/lang/String;");

        Ref base64Decode = method(u"Landroid/util/Base64;", u"decode", u"[B", {STRING, u"I"});
        Ref arrayNewInstance = method(u"Ljava/lang/reflect/Array;", u"newInstance", OBJECT, {OBJECT_CLASS, u"I"});
        const Text APPLICATION = u"Landroid/app/Application;";
        Ref objectInit = method(OBJECT, u"<init>", u"V");
        Ref superInit = method(APPLICATION, u"<init>", u"V");
        Ref superAttach = method(APPLICATION, u"attachBaseContext", u"V", {CONTEXT});
        Ref objectClass = method(OBJECT, u"getClass", OBJECT_CLASS);
        Ref classForName = method(u"Ljava/lang/Class;", u"forName", OBJECT_CLASS, {STRING});
        Ref getDeclaredField = method(u"Ljava/lang/Class;", u"getDeclaredField", FIELD, {STRING});
        Ref setAccessible = method(FIELD, u"setAccessible", u"V", {u"Z"});
        Ref fieldGet = method(FIELD, u"get", OBJECT, {OBJECT});
        Ref fieldSet = method(FIELD, u"set", u"V", {OBJECT, OBJECT});
        Ref contextLoader = method(CONTEXT, u"getClassLoader", LOADER);
        Ref contextManager = method(CONTEXT, u"getPackageManager", u"Landroid/content/pm/PackageManager;");
        Ref proxyNew = method(u"Ljava/lang/reflect/Proxy;", u"newProxyInstance", OBJECT,
                {LOADER, u"[Ljava/lang/Class;", HANDLER_INTERFACE});
        Ref methodName = method(METHOD, u"getName", STRING);
        Ref methodInvoke = method(METHOD, u"invoke", OBJECT, {OBJECT, u"[Ljava/lang/Object;"});
        Ref stringEquals = method(u"Ljava/lang/String;", u"equals", u"Z", {OBJECT});
        Ref objectEquals = method(OBJECT, u"equals", u"Z", {OBJECT});
        Ref signatureInit = method(SIGNATURE, u"<init>", u"V", {u"[B"});
        Ref fileInit = method(u"Ljava/io/File;", u"<init>", u"V", {STRING});
        Ref fileParentInit = method(u"Ljava/io/File;", u"<init>", u"V",
                {u"Ljava/io/File;", STRING});
        Ref fileExists = method(u"Ljava/io/File;", u"exists", u"Z");
        Ref fileMkdirs = method(u"Ljava/io/File;", u"mkdirs", u"Z");
        Ref fileAbsolute = method(u"Ljava/io/File;", u"getAbsolutePath", STRING);
        Ref contextFiles = method(CONTEXT, u"getFilesDir", u"Ljava/io/File;");
        Ref contextAssets = method(CONTEXT, u"getAssets", u"Landroid/content/res/AssetManager;");
        Ref contextCodePath = method(CONTEXT, u"getPackageCodePath", STRING);
        Ref assetOpen = method(u"Landroid/content/res/AssetManager;", u"open",
                u"Ljava/io/InputStream;", {STRING});
        Ref outputInit = method(u"Ljava/io/FileOutputStream;", u"<init>", u"V",
                {u"Ljava/io/File;"});
        Ref inputRead = method(u"Ljava/io/InputStream;", u"read", u"I", {u"[B"});
        Ref outputWrite = method(u"Ljava/io/FileOutputStream;", u"write", u"V",
                {u"[B", u"I", u"I"});
        Ref inputClose = method(u"Ljava/io/InputStream;", u"close", u"V");
        Ref outputClose = method(u"Ljava/io/FileOutputStream;", u"close", u"V");

        Ref appInit = method(proxy, u"<init>", u"V");
        Ref appClinit = method(proxy, u"<clinit>", u"V");
        Ref attach = method(proxy, u"attachBaseContext", u"V", {CONTEXT});
        Ref install = method(proxy, u"$install", u"V", {CONTEXT});
        Ref fieldHelper = method(proxy, u"$field", FIELD, {OBJECT_CLASS, STRING});
        Ref patchPackage = method(proxy, u"$patchPackage", u"V", {PACKAGE_INFO});
        Ref patchApplication = method(proxy, u"$patchApplicationInfo", u"V", {APPLICATION_INFO});
        Ref originalPath = method(proxy, u"$originalApkPath", STRING);
        Ref extractApk = method(proxy, u"$extractApk", STRING, {CONTEXT});
        Ref fake = method(proxy, u"$fakeSignatures", SIGNATURE_ARRAY);
        Ref patchSigning = method(proxy, u"$patchSigningInfo", u"V", {OBJECT, SIGNATURE_ARRAY});
        Ref handlerInit = method(handler, u"<init>", u"V");
        Ref handlerInvoke = method(handler, u"invoke", OBJECT,
                {OBJECT, METHOD, u"[Ljava/lang/Object;"});

        dex::Class app;
        app.type = proxy;
        app.super = APPLICATION;
        app.flags = 0x1;
        dex::Field certificateStorage;
        certificateStorage.ref = certField;
        certificateStorage.flags = 0xa;
        dex::Field originalStorage;
        originalStorage.ref = originalField;
        originalStorage.flags = 0xa;
        dex::Field apkPathStorage;
        apkPathStorage.ref = apkPathField;
        apkPathStorage.flags = 0xa;
        app.staticFields.push_back(certificateStorage);
        app.staticFields.push_back(originalStorage);
        app.staticFields.push_back(apkPathStorage);

        Builder constructor;
        constructor.add(call(superInit, 0, 1, 0x76));
        constructor.add(raw({0x0e}));
        app.direct.push_back(newMethod(appInit, 0x10001, constructor.build(1, 1, 1)));

        Builder initializer;
        initializer.add(string(0, utf16(base64(cert))));
        initializer.add(constant(1, 0));
        initializer.add(call(base64Decode, 0, 2, 0x77));
        initializer.add(resultObject(0));
        initializer.add(field21(0x69, 0, certField));
        initializer.add(raw({0x0e}));
        app.direct.push_back(newMethod(appClinit, 0x8, initializer.build(2, 0, 3)));

        Builder attachCode;
        // ins=2: p0=this(v2), p1=base(v3)
        attachCode.add(moveObject(0,2));
        attachCode.add(moveObject(1,3));
        attachCode.add(call(extractApk, 0, 1, 0x77)); attachCode.add(resultObject(0));
        attachCode.add(moveObject(0,2));
        attachCode.add(call(install, 0, 1, 0x77));
        attachCode.add(moveObject(0,2)); attachCode.add(moveObject(1,3));
        attachCode.add(call(superAttach, 0, 2, 0x75));
        attachCode.add(raw({0x0e}));
        uint32_t attachH = uint32_t(attachCode.instructions.size());
        attachCode.add(raw({uint16_t(0x0d|(0<<8))})); attachCode.add(raw({0x0e}));
        app.virtuals.push_back(newMethod(attach, 0x1, attachCode.build(4, 2, 2, attachH)));

        Builder fieldCode;
        fieldCode.add(moveObject(0, 2));
        fieldCode.add(moveObject(1, 3));
        fieldCode.add(call(getDeclaredField, 2, 2, 0x74));
        fieldCode.add(resultObject(0));
        fieldCode.add(constant(1, 1));
        fieldCode.add(call(setAccessible, 0, 2, 0x74));
        fieldCode.add(raw({0x11, 0}));
        app.direct.push_back(newMethod(fieldHelper, 0x8, fieldCode.build(4, 2, 3)));

        Builder installCode;
        installCode.add(moveObject(0, 6));
        installCode.add(string(0, u"android.app.ActivityThread"));
        installCode.add(call(classForName, 0, 1, 0x77));
        installCode.add(resultObject(0));
        installCode.add(moveObject(1, 0));
        installCode.add(string(2, u"sPackageManager"));
        installCode.add(call(fieldHelper, 1, 2, 0x77));
        installCode.add(resultObject(1));
        installCode.add(constant(2, 0));
        installCode.add(call(fieldGet, 1, 2, 0x74));
        installCode.add(resultObject(0));
        installCode.add(field21(0x69, 0, originalField));
        installCode.add(call(contextLoader, 6, 1, 0x74));
        installCode.add(resultObject(2));
        installCode.add(typeOp(0x1c, 3, OBJECT_CLASS));
        installCode.add(constant(4, 1));
        installCode.add(call(arrayNewInstance, 3, 2, 0x77));
        installCode.add(resultObject(3));
        installCode.add(call(objectClass, 0, 1, 0x74));
        installCode.add(resultObject(4));
        installCode.add(constant(5, 0));
        installCode.add(three(0x4d, 4, 3, 5));
        installCode.add(typeOp(0x22, 4, handler));
        installCode.add(call(handlerInit, 4, 1, 0x76));
        installCode.add(call(proxyNew, 2, 3, 0x77));
        installCode.add(resultObject(2));
        installCode.add(moveObject(3, 2));
        installCode.add(constant(2, 0));
        installCode.add(call(fieldSet, 1, 3, 0x74));
        installCode.add(call(contextManager, 6, 1, 0x74));
        installCode.add(resultObject(5));
        installCode.add(call(objectClass, 5, 1, 0x74));
        installCode.add(resultObject(0));
        installCode.add(string(1, u"mPM"));
        installCode.add(call(fieldHelper, 0, 2, 0x77));
        installCode.add(resultObject(0));
        installCode.add(moveObject(1, 5));
        installCode.add(moveObject(2, 3));
        installCode.add(call(fieldSet, 0, 3, 0x74));
        installCode.add(raw({0x0e}));
        uint32_t installHandler = uint32_t(installCode.instructions.size());
        installCode.add(raw({uint16_t(0x0d)}));
        installCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(install, 0x8, installCode.build(7, 1, 3, installHandler)));

        Builder patchCode;
        patchCode.add(moveObject(0, 3));
        patchCode.add(call(fake, 0, 0, 0x77));
        patchCode.add(resultObject(0));
        patchCode.add(field22(0x5b, 0, 3, signaturesField));
        patchCode.add(field22(0x54, 1, 3, applicationInfoField));
        uint32_t appBranch = uint32_t(patchCode.instructions.size());
        patchCode.add(raw({uint16_t(0x38 | (1 << 8)), 0}));
        patchCode.add(call(patchApplication, 1, 1, 0x77));
        patchCode.instructions[appBranch].target = uint32_t(patchCode.instructions.size());
        patchCode.add(field22(0x54, 1, 3, signingInfoField));
        uint32_t signingBranch = uint32_t(patchCode.instructions.size());
        patchCode.add(raw({uint16_t(0x38 | (1 << 8)), 0}));
        patchCode.add(moveObject(2, 0));
        patchCode.add(call(patchSigning, 1, 2, 0x77));
        patchCode.instructions[signingBranch].target = uint32_t(patchCode.instructions.size());
        patchCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchPackage, 0x8, patchCode.build(4, 1, 3)));

        Builder signatures;
        signatures.add(field21(0x62, 0, certField));
        signatures.add(constant(3, 1));
        signatures.add(typeOp(0x1c, 2, SIGNATURE));
        signatures.add(call(arrayNewInstance, 2, 2, 0x77));
        signatures.add(resultObject(2));
        signatures.add(typeOp(0x1f, 2, SIGNATURE_ARRAY));
        signatures.add(typeOp(0x22, 3, SIGNATURE));
        signatures.add(moveObject(4, 0));
        signatures.add(call(signatureInit, 3, 2, 0x76));
        signatures.add(constant(4, 0));
        signatures.add(three(0x4d, 3, 2, 4));
        signatures.add(raw({uint16_t(0x11|(2<<8)),0}));
        app.direct.push_back(newMethod(fake, 0x8, signatures.build(5, 0, 3)));

        Builder signing;
        signing.add(moveObject(5, 0));
        signing.add(moveObject(4, 1));
        signing.add(call(objectClass, 5, 1, 0x74));
        signing.add(resultObject(0));
        signing.add(string(1, u"mApkContentsSigners"));
        signing.add(call(getDeclaredField, 0, 2, 0x74));
        signing.add(resultObject(1));
        signing.add(constant(2, 1));
        signing.add(call(setAccessible, 1, 2, 0x74));
        signing.add(moveObject(2, 5));
        signing.add(moveObject(3, 4));
        signing.add(call(fieldSet, 1, 3, 0x74));
        signing.add(call(objectClass, 5, 1, 0x74));
        signing.add(resultObject(0));
        signing.add(string(1, u"mSigningCertificateHistory"));
        signing.add(call(getDeclaredField, 0, 2, 0x74));
        signing.add(resultObject(1));
        signing.add(constant(2, 1));
        signing.add(call(setAccessible, 1, 2, 0x74));
        signing.add(moveObject(2, 5));
        signing.add(moveObject(3, 4));
        signing.add(call(fieldSet, 1, 3, 0x74));
        signing.add(raw({0x0e}));
        uint32_t signingHandler = uint32_t(signing.instructions.size());
        signing.add(raw({uint16_t(0x0d)}));
        signing.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchSigning, 0x8,
                signing.build(6, 2, 3, signingHandler)));

        Builder applicationCode;
        applicationCode.add(moveObject(6, 0));
        applicationCode.add(field21(0x62, 0, apkPathField));
        uint32_t skipApplication = uint32_t(applicationCode.instructions.size());
        applicationCode.add(raw({uint16_t(0x38), 0}));
        applicationCode.add(field22(0x5b, 0, 6, sourceDirField));
        applicationCode.add(field22(0x5b, 0, 6, publicSourceDirField));
        applicationCode.add(constant(1, 1));
        applicationCode.add(arrayOp(0x23, 2, 1, u"[Ljava/lang/String;"));
        applicationCode.add(constant(1, 0));
        applicationCode.add(three(0x4d, 0, 2, 1));
        applicationCode.add(field22(0x5b, 2, 6, splitSourceDirsField));
        applicationCode.instructions[skipApplication].target = uint32_t(applicationCode.instructions.size());
        applicationCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchApplication, 0x8,
                applicationCode.build(7, 1, 3)));

        Builder pathCode;
        pathCode.add(field21(0x62, 0, apkPathField));
        pathCode.add(raw({0x11, 0}));
        app.direct.push_back(newMethod(originalPath, 0x8, pathCode.build(1, 0, 1)));

        Builder extractCode;
        extractCode.add(moveObject(0, 9));
        extractCode.add(field21(0x62, 1, apkPathField));
        uint32_t havePath = uint32_t(extractCode.instructions.size());
        extractCode.add(raw({uint16_t(0x39 | (1<<8)), 0})); // if-nez v1, ret
        extractCode.add(call(contextCodePath, 0, 1, 0x74));
        extractCode.add(resultObject(1));
        extractCode.add(field21(0x69, 1, apkPathField));
        extractCode.instructions[havePath].target = uint32_t(extractCode.instructions.size());
        extractCode.add(field21(0x62, 0, apkPathField));
        extractCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        app.direct.push_back(newMethod(extractApk, 0x8,
                extractCode.build(10, 1, 1)));

        dex::Class proxyClass;
        proxyClass.type = handler;
        proxyClass.super = u"Ljava/lang/Object;";
        proxyClass.flags = 0x1;
        proxyClass.interfaces.push_back(HANDLER_INTERFACE);

        Builder handlerConstructor;
        handlerConstructor.add(call(objectInit, 0, 1, 0x76));
        handlerConstructor.add(raw({0x0e}));
        proxyClass.direct.push_back(newMethod(handlerInit, 0x10001,
                handlerConstructor.build(1, 1, 1)));

        Builder invokeCode;
        // regs=8, ins=4? invoke(Object proxy, Method method, Object[] args) => 3 params + this
        // ins=4: p0=this(v4), p1=proxy(v5), p2=method(v6), p3=args(v7)
        invokeCode.add(field21(0x62, 1, originalField)); // v1 = original PM
        invokeCode.add(moveObject(2,6)); // v2 = method
        invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2)); // v2 = name
        // if name == "getPackageInfo"
        invokeCode.add(string(3,u"getPackageInfo"));
        invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
        uint32_t bNotPkg = uint32_t(invokeCode.instructions.size());
        invokeCode.add(raw({uint16_t(0x38 | (3<<8)), 0})); // if-eqz v3, notPkg
        // invoke original
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(typeOp(0x1f,0,PACKAGE_INFO));
        invokeCode.add(call(patchPackage,0,1,0x77));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t notPkg = uint32_t(invokeCode.instructions.size());
        invokeCode.instructions[bNotPkg].target = notPkg;
        // if name == "getPackageArchiveInfo"
        invokeCode.add(moveObject(2,6));
        invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2));
        invokeCode.add(string(3,u"getPackageArchiveInfo"));
        invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
        uint32_t bNotArch = uint32_t(invokeCode.instructions.size());
        invokeCode.add(raw({uint16_t(0x38 | (3<<8)), 0}));
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(typeOp(0x1f,0,PACKAGE_INFO));
        invokeCode.add(call(patchPackage,0,1,0x77));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t notArch = uint32_t(invokeCode.instructions.size());
        invokeCode.instructions[bNotArch].target = notArch;
        // if name == "getApplicationInfo"
        invokeCode.add(moveObject(2,6));
        invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2));
        invokeCode.add(string(3,u"getApplicationInfo"));
        invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
        uint32_t bNotApp = uint32_t(invokeCode.instructions.size());
        invokeCode.add(raw({uint16_t(0x38 | (3<<8)), 0}));
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(typeOp(0x1f,0,APPLICATION_INFO));
        invokeCode.add(call(patchApplication,0,1,0x77));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t notApp = uint32_t(invokeCode.instructions.size());
        invokeCode.instructions[bNotApp].target = notApp;
        // default: invoke original
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        proxyClass.virtuals.push_back(newMethod(handlerInvoke, 0x1, invokeCode.build(8, 4, 4)));

        if (progress) progress("Finishing Binder proxy", 60);
        dex::Model model;
        model.classes.push_back(app);
        model.classes.push_back(proxyClass);
        SignatureResult result;
        result.bytes = dex::write(model);
        validateDex(result.bytes);
        result.report.classes = 2;
        result.report.methods = 13;
        result.report.sites = cert.size();
        result.changed = true;
        return result;
    }
    SignatureResult killSignaturesV3(const Archive& apk, const SignatureOptions& options, const Progress& progress) {
        using namespace dex;
        if (progress) progress("Reading original signature", 20);
        Bytes cert = originalCertificate(apk);
        const Text proxy = options.className;
        const Text handler = proxy.substr(0, proxy.size() - 1) + u"$PmsHookBinderInvocationHandler;";
        require(!options.classes.count(proxy) && !options.classes.count(handler),
                "Signature killer v3 class collision.");
        require(!options.originalApkAsset.empty(), "Signature killer v3 needs an original APK asset.");

        const auto& cfg = options.v3;
        const bool doPmProxy = cfg.pmProxy;
        const bool doPatchSigning = cfg.patchSigningInfo;
        const bool doReplacePath = cfg.replaceApkPath;
        const bool doPatchAppInfo = cfg.patchApplicationInfo;

        if (progress) progress("Building Binder proxy", 40);
        const Text OBJECT_CLASS = u"Ljava/lang/Class;";
        const Text STRING = u"Ljava/lang/String;";
        const Text CONTEXT = u"Landroid/content/Context;";
        const Text LOADER = u"Ljava/lang/ClassLoader;";
        const Text METHOD = u"Ljava/lang/reflect/Method;";
        const Text FIELD = u"Ljava/lang/reflect/Field;";
        const Text HANDLER_INTERFACE = u"Ljava/lang/reflect/InvocationHandler;";

        Ref certField = field(proxy, u"certificate", u"[B");
        Ref originalField = field(proxy, u"original", OBJECT);
        Ref apkPathField = field(proxy, u"originalApkPath", STRING);
        Ref signaturesField = field(PACKAGE_INFO, u"signatures", SIGNATURE_ARRAY);
        Ref signingInfoField = field(PACKAGE_INFO, u"signingInfo", u"Landroid/content/pm/SigningInfo;");
        Ref applicationInfoField = field(PACKAGE_INFO, u"applicationInfo", APPLICATION_INFO);
        Ref sourceDirField = field(APPLICATION_INFO, u"sourceDir", STRING);
        Ref publicSourceDirField = field(APPLICATION_INFO, u"publicSourceDir", STRING);
        Ref splitSourceDirsField = field(APPLICATION_INFO, u"splitSourceDirs", u"[Ljava/lang/String;");

        Ref base64Decode = method(u"Landroid/util/Base64;", u"decode", u"[B", {STRING, u"I"});
        Ref arrayNewInstance = method(u"Ljava/lang/reflect/Array;", u"newInstance", OBJECT, {OBJECT_CLASS, u"I"});
        const Text APPLICATION = u"Landroid/app/Application;";
        Ref objectInit = method(OBJECT, u"<init>", u"V");
        Ref superInit = method(APPLICATION, u"<init>", u"V");
        Ref superAttach = method(APPLICATION, u"attachBaseContext", u"V", {CONTEXT});
        Ref objectClass = method(OBJECT, u"getClass", OBJECT_CLASS);
        Ref classForName = method(u"Ljava/lang/Class;", u"forName", OBJECT_CLASS, {STRING});
        Ref getDeclaredField = method(u"Ljava/lang/Class;", u"getDeclaredField", FIELD, {STRING});
        Ref setAccessible = method(FIELD, u"setAccessible", u"V", {u"Z"});
        Ref fieldGet = method(FIELD, u"get", OBJECT, {OBJECT});
        Ref fieldSet = method(FIELD, u"set", u"V", {OBJECT, OBJECT});
        Ref contextLoader = method(CONTEXT, u"getClassLoader", LOADER);
        Ref contextManager = method(CONTEXT, u"getPackageManager", u"Landroid/content/pm/PackageManager;");
        Ref proxyNew = method(u"Ljava/lang/reflect/Proxy;", u"newProxyInstance", OBJECT,
                {LOADER, u"[Ljava/lang/Class;", HANDLER_INTERFACE});
        Ref methodName = method(METHOD, u"getName", STRING);
        Ref methodInvoke = method(METHOD, u"invoke", OBJECT, {OBJECT, u"[Ljava/lang/Object;"});
        Ref stringEquals = method(u"Ljava/lang/String;", u"equals", u"Z", {OBJECT});
        Ref signatureInit = method(SIGNATURE, u"<init>", u"V", {u"[B"});
        Ref fileParentInit = method(u"Ljava/io/File;", u"<init>", u"V", {u"Ljava/io/File;", STRING});
        Ref fileExists = method(u"Ljava/io/File;", u"exists", u"Z");
        Ref fileMkdirs = method(u"Ljava/io/File;", u"mkdirs", u"Z");
        Ref fileAbsolute = method(u"Ljava/io/File;", u"getAbsolutePath", STRING);
        Ref contextFiles = method(CONTEXT, u"getFilesDir", u"Ljava/io/File;");
        Ref contextAssets = method(CONTEXT, u"getAssets", u"Landroid/content/res/AssetManager;");
        Ref contextCodePath = method(CONTEXT, u"getPackageCodePath", STRING);
        Ref assetOpen = method(u"Landroid/content/res/AssetManager;", u"open", u"Ljava/io/InputStream;", {STRING});
        Ref outputInit = method(u"Ljava/io/FileOutputStream;", u"<init>", u"V", {u"Ljava/io/File;"});
        Ref inputRead = method(u"Ljava/io/InputStream;", u"read", u"I", {u"[B"});
        Ref outputWrite = method(u"Ljava/io/FileOutputStream;", u"write", u"V", {u"[B", u"I", u"I"});
        Ref inputClose = method(u"Ljava/io/InputStream;", u"close", u"V");
        Ref outputClose = method(u"Ljava/io/FileOutputStream;", u"close", u"V");

        Ref appInit = method(proxy, u"<init>", u"V");
        Ref appClinit = method(proxy, u"<clinit>", u"V");
        Ref attach = method(proxy, u"attachBaseContext", u"V", {CONTEXT});
        Ref install = method(proxy, u"$install", u"V", {CONTEXT});
        Ref fieldHelper = method(proxy, u"$field", FIELD, {OBJECT_CLASS, STRING});
        Ref patchPackage = method(proxy, u"$patchPackage", u"V", {PACKAGE_INFO});
        Ref patchApplication = method(proxy, u"$patchApplicationInfo", u"V", {APPLICATION_INFO});
        Ref originalPath = method(proxy, u"$originalApkPath", STRING);
        Ref extractApk = method(proxy, u"$extractApk", STRING, {CONTEXT});
        Ref fake = method(proxy, u"$fakeSignatures", SIGNATURE_ARRAY);
        Ref patchSigning = method(proxy, u"$patchSigningInfo", u"V", {OBJECT, SIGNATURE_ARRAY});
        Ref handlerInit = method(handler, u"<init>", u"V");
        Ref handlerInvoke = method(handler, u"invoke", OBJECT, {OBJECT, METHOD, u"[Ljava/lang/Object;"});

        dex::Class app;
        app.type = proxy;
        app.super = APPLICATION;
        app.flags = 0x1;
        dex::Field certificateStorage; certificateStorage.ref = certField; certificateStorage.flags = 0xa;
        dex::Field originalStorage; originalStorage.ref = originalField; originalStorage.flags = 0xa;
        dex::Field apkPathStorage; apkPathStorage.ref = apkPathField; apkPathStorage.flags = 0xa;
        app.staticFields.push_back(certificateStorage);
        app.staticFields.push_back(originalStorage);
        app.staticFields.push_back(apkPathStorage);

        Builder constructor;
        constructor.add(call(superInit, 0, 1, 0x76));
        constructor.add(raw({0x0e}));
        app.direct.push_back(newMethod(appInit, 0x10001, constructor.build(1, 1, 1)));

        Builder initializer;
        initializer.add(string(0, utf16(base64(cert))));
        initializer.add(constant(1, 0));
        initializer.add(call(base64Decode, 0, 2, 0x77));
        initializer.add(resultObject(0));
        initializer.add(field21(0x69, 0, certField));
        initializer.add(raw({0x0e}));
        app.direct.push_back(newMethod(appClinit, 0x8, initializer.build(2, 0, 3)));

        Builder attachCode;
        // ins=2: p0=this(v2), p1=base(v3)
        attachCode.add(moveObject(0,2));
        attachCode.add(moveObject(1,3));
        if (doReplacePath || doPatchAppInfo) {
            attachCode.add(call(extractApk, 0, 1, 0x77)); attachCode.add(resultObject(0));
            attachCode.add(moveObject(0,2));
        }
        if (doPmProxy) {
            attachCode.add(call(install, 0, 1, 0x77));
            attachCode.add(moveObject(0,2)); attachCode.add(moveObject(1,3));
        }
        attachCode.add(call(superAttach, 0, 2, 0x75));
        attachCode.add(raw({0x0e}));
        uint32_t attachH = uint32_t(attachCode.instructions.size());
        attachCode.add(raw({uint16_t(0x0d|(0<<8))})); attachCode.add(raw({0x0e}));
        app.virtuals.push_back(newMethod(attach, 0x1, attachCode.build(4, 2, 2, attachH)));

        Builder fieldCode;
        fieldCode.add(moveObject(0, 2));
        fieldCode.add(moveObject(1, 3));
        fieldCode.add(call(getDeclaredField, 2, 2, 0x74));
        fieldCode.add(resultObject(0));
        fieldCode.add(constant(1, 1));
        fieldCode.add(call(setAccessible, 0, 2, 0x74));
        fieldCode.add(raw({0x11, 0}));
        app.direct.push_back(newMethod(fieldHelper, 0x8, fieldCode.build(4, 2, 3)));

        Builder installCode;
        installCode.add(moveObject(0, 6));
        installCode.add(string(0, u"android.app.ActivityThread"));
        installCode.add(call(classForName, 0, 1, 0x77));
        installCode.add(resultObject(0));
        installCode.add(moveObject(1, 0));
        installCode.add(string(2, u"sPackageManager"));
        installCode.add(call(fieldHelper, 1, 2, 0x77));
        installCode.add(resultObject(1));
        installCode.add(constant(2, 0));
        installCode.add(call(fieldGet, 1, 2, 0x74));
        installCode.add(resultObject(0));
        installCode.add(field21(0x69, 0, originalField));
        installCode.add(call(contextLoader, 6, 1, 0x74));
        installCode.add(resultObject(2));
        installCode.add(typeOp(0x1c, 3, OBJECT_CLASS));
        installCode.add(constant(4, 1));
        installCode.add(call(arrayNewInstance, 3, 2, 0x77));
        installCode.add(resultObject(3));
        installCode.add(call(objectClass, 0, 1, 0x74));
        installCode.add(resultObject(4));
        installCode.add(constant(5, 0));
        installCode.add(three(0x4d, 4, 3, 5));
        installCode.add(typeOp(0x22, 4, handler));
        installCode.add(call(handlerInit, 4, 1, 0x76));
        installCode.add(call(proxyNew, 2, 3, 0x77));
        installCode.add(resultObject(2));
        installCode.add(moveObject(3, 2));
        installCode.add(constant(2, 0));
        installCode.add(call(fieldSet, 1, 3, 0x74));
        installCode.add(call(contextManager, 6, 1, 0x74));
        installCode.add(resultObject(5));
        installCode.add(call(objectClass, 5, 1, 0x74));
        installCode.add(resultObject(0));
        installCode.add(string(1, u"mPM"));
        installCode.add(call(fieldHelper, 0, 2, 0x77));
        installCode.add(resultObject(0));
        installCode.add(moveObject(1, 5));
        installCode.add(moveObject(2, 3));
        installCode.add(call(fieldSet, 0, 3, 0x74));
        installCode.add(raw({0x0e}));
        uint32_t installHandler = uint32_t(installCode.instructions.size());
        installCode.add(raw({uint16_t(0x0d)}));
        installCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(install, 0x8, installCode.build(7, 1, 3, installHandler)));

        Builder patchCode;
        patchCode.add(moveObject(0, 3));
        patchCode.add(call(fake, 0, 0, 0x77));
        patchCode.add(resultObject(0));
        patchCode.add(field22(0x5b, 0, 3, signaturesField));
        if (doPatchAppInfo || doReplacePath) {
            patchCode.add(field22(0x54, 1, 3, applicationInfoField));
            uint32_t appBranch = uint32_t(patchCode.instructions.size());
            patchCode.add(raw({uint16_t(0x38 | (1 << 8)), 0}));
            patchCode.add(call(patchApplication, 1, 1, 0x77));
            patchCode.instructions[appBranch].target = uint32_t(patchCode.instructions.size());
        }
        if (doPatchSigning) {
            patchCode.add(field22(0x54, 1, 3, signingInfoField));
            uint32_t signingBranch = uint32_t(patchCode.instructions.size());
            patchCode.add(raw({uint16_t(0x38 | (1 << 8)), 0}));
            patchCode.add(moveObject(2, 0));
            patchCode.add(call(patchSigning, 1, 2, 0x77));
            patchCode.instructions[signingBranch].target = uint32_t(patchCode.instructions.size());
        }
        patchCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchPackage, 0x8, patchCode.build(4, 1, 3)));

        Builder signatures;
        signatures.add(field21(0x62, 0, certField));
        signatures.add(constant(3, 1));
        signatures.add(typeOp(0x1c, 2, SIGNATURE));
        signatures.add(call(arrayNewInstance, 2, 2, 0x77));
        signatures.add(resultObject(2));
        signatures.add(typeOp(0x1f, 2, SIGNATURE_ARRAY));
        signatures.add(typeOp(0x22, 3, SIGNATURE));
        signatures.add(moveObject(4, 0));
        signatures.add(call(signatureInit, 3, 2, 0x76));
        signatures.add(constant(4, 0));
        signatures.add(three(0x4d, 3, 2, 4));
        signatures.add(raw({uint16_t(0x11|(2<<8)),0}));
        app.direct.push_back(newMethod(fake, 0x8, signatures.build(5, 0, 3)));

        Builder signing;
        signing.add(moveObject(5, 0));
        signing.add(moveObject(4, 1));
        signing.add(call(objectClass, 5, 1, 0x74));
        signing.add(resultObject(0));
        signing.add(string(1, u"mApkContentsSigners"));
        signing.add(call(getDeclaredField, 0, 2, 0x74));
        signing.add(resultObject(1));
        signing.add(constant(2, 1));
        signing.add(call(setAccessible, 1, 2, 0x74));
        signing.add(moveObject(2, 5));
        signing.add(moveObject(3, 4));
        signing.add(call(fieldSet, 1, 3, 0x74));
        signing.add(call(objectClass, 5, 1, 0x74));
        signing.add(resultObject(0));
        signing.add(string(1, u"mSigningCertificateHistory"));
        signing.add(call(getDeclaredField, 0, 2, 0x74));
        signing.add(resultObject(1));
        signing.add(constant(2, 1));
        signing.add(call(setAccessible, 1, 2, 0x74));
        signing.add(moveObject(2, 5));
        signing.add(moveObject(3, 4));
        signing.add(call(fieldSet, 1, 3, 0x74));
        signing.add(raw({0x0e}));
        uint32_t signingHandler = uint32_t(signing.instructions.size());
        signing.add(raw({uint16_t(0x0d)}));
        signing.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchSigning, 0x8, signing.build(6, 2, 3, signingHandler)));

        Builder applicationCode;
        applicationCode.add(moveObject(6, 0));
        applicationCode.add(field21(0x62, 0, apkPathField));
        uint32_t skipApplication = uint32_t(applicationCode.instructions.size());
        applicationCode.add(raw({uint16_t(0x38), 0}));
        if (doReplacePath) {
            applicationCode.add(field22(0x5b, 0, 6, sourceDirField));
            applicationCode.add(field22(0x5b, 0, 6, publicSourceDirField));
        }
        if (doPatchAppInfo) {
            applicationCode.add(constant(1, 1));
            applicationCode.add(arrayOp(0x23, 2, 1, u"[Ljava/lang/String;"));
            applicationCode.add(constant(1, 0));
            applicationCode.add(three(0x4d, 0, 2, 1));
            applicationCode.add(field22(0x5b, 2, 6, splitSourceDirsField));
        }
        applicationCode.instructions[skipApplication].target = uint32_t(applicationCode.instructions.size());
        applicationCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchApplication, 0x8, applicationCode.build(7, 1, 3)));

        Builder pathCode;
        pathCode.add(field21(0x62, 0, apkPathField));
        pathCode.add(raw({0x11, 0}));
        app.direct.push_back(newMethod(originalPath, 0x8, pathCode.build(1, 0, 1)));

        Builder extractCode;
        extractCode.add(moveObject(0, 9));
        extractCode.add(field21(0x62, 1, apkPathField));
        uint32_t havePath3 = uint32_t(extractCode.instructions.size());
        extractCode.add(raw({uint16_t(0x39 | (1<<8)), 0}));
        extractCode.add(call(contextCodePath, 0, 1, 0x74));
        extractCode.add(resultObject(1));
        extractCode.add(field21(0x69, 1, apkPathField));
        extractCode.instructions[havePath3].target = uint32_t(extractCode.instructions.size());
        extractCode.add(field21(0x62, 0, apkPathField));
        extractCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        app.direct.push_back(newMethod(extractApk, 0x8, extractCode.build(10, 1, 1)));

        dex::Class proxyClass;
        proxyClass.type = handler;
        proxyClass.super = u"Ljava/lang/Object;";
        proxyClass.flags = 0x1;
        proxyClass.interfaces.push_back(HANDLER_INTERFACE);

        Builder handlerConstructor;
        handlerConstructor.add(call(objectInit, 0, 1, 0x76));
        handlerConstructor.add(raw({0x0e}));
        proxyClass.direct.push_back(newMethod(handlerInit, 0x10001, handlerConstructor.build(1, 1, 1)));

        Builder invokeCode;
        // ins=4: this=v4,proxy=v5,method=v6,args=v7
        invokeCode.add(field21(0x62, 1, originalField));
        invokeCode.add(moveObject(2,6));
        invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2));
        invokeCode.add(string(3,u"getPackageInfo"));
        invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
        uint32_t bNotPkg = uint32_t(invokeCode.instructions.size());
        invokeCode.add(raw({uint16_t(0x38 | (3<<8)), 0}));
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(typeOp(0x1f,0,PACKAGE_INFO));
        invokeCode.add(call(patchPackage,0,1,0x77));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t notPkg = uint32_t(invokeCode.instructions.size());
        invokeCode.instructions[bNotPkg].target = notPkg;
        invokeCode.add(moveObject(2,6));
        invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2));
        invokeCode.add(string(3,u"getPackageArchiveInfo"));
        invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
        uint32_t bNotArch = uint32_t(invokeCode.instructions.size());
        invokeCode.add(raw({uint16_t(0x38 | (3<<8)), 0}));
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(typeOp(0x1f,0,PACKAGE_INFO));
        invokeCode.add(call(patchPackage,0,1,0x77));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t notArch = uint32_t(invokeCode.instructions.size());
        invokeCode.instructions[bNotArch].target = notArch;
        invokeCode.add(moveObject(2,6));
        invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2));
        invokeCode.add(string(3,u"getApplicationInfo"));
        invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
        uint32_t bNotApp = uint32_t(invokeCode.instructions.size());
        invokeCode.add(raw({uint16_t(0x38 | (3<<8)), 0}));
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(typeOp(0x1f,0,APPLICATION_INFO));
        if (doPatchAppInfo || doReplacePath) {
            invokeCode.add(call(patchApplication,0,1,0x77));
        }
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t notApp = uint32_t(invokeCode.instructions.size());
        invokeCode.instructions[bNotApp].target = notApp;
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        proxyClass.virtuals.push_back(newMethod(handlerInvoke, 0x1, invokeCode.build(8, 4, 4)));

        if (progress) progress("Finishing Binder proxy", 60);
        dex::Model model;
        model.classes.push_back(app);
        model.classes.push_back(proxyClass);
        SignatureResult result;
        result.bytes = dex::write(model);
        validateDex(result.bytes);
        result.report.classes = 2;
        result.report.methods = 13;
        result.report.sites = cert.size();
        result.changed = true;
        return result;
    }

    SignatureResult killSignaturesV4(const Archive& apk, const SignatureOptions& options, const Progress& progress) {
        using namespace dex;
        if (progress) progress("Reading original signature", 20);
        Bytes cert = originalCertificate(apk);
        const Text proxy = options.className;
        const Text handler = proxy.substr(0, proxy.size() - 1) + u"$PmsHookBinderInvocationHandler;";
        const Text factory = options.factoryName.empty() ? u"Lio/dexpack/sigkill4/ProxyComponentFactory;" : options.factoryName;
        require(!options.classes.count(proxy) && !options.classes.count(handler) && !options.classes.count(factory),
                "Signature killer v4 class collision.");
        const auto& cfg = options.v4;
        const bool doEmbed = cfg.embedOriginalApk || cfg.replaceApkPath || cfg.patchApplicationInfo;
        if (doEmbed) require(!options.originalApkAsset.empty(), "Signature killer v4 needs an original APK asset.");

        if (progress) progress("Building Fancy-style proxy", 40);
        const Text OBJECT_CLASS = u"Ljava/lang/Class;";
        const Text STRING = u"Ljava/lang/String;";
        const Text CONTEXT = u"Landroid/content/Context;";
        const Text LOADER = u"Ljava/lang/ClassLoader;";
        const Text METHOD = u"Ljava/lang/reflect/Method;";
        const Text FIELD = u"Ljava/lang/reflect/Field;";
        const Text HANDLER_INTERFACE = u"Ljava/lang/reflect/InvocationHandler;";
        const Text APPLICATION = u"Landroid/app/Application;";
        Text originalApp = u"L" + options.applicationName;
        for (auto& c : originalApp) if (c == u'.') c = u'/';
        originalApp += u";";
        Text helperName = proxy.substr(1, proxy.size() - 2);
        for (auto& c : helperName) if (c == u'/') c = u'.';

        Ref certField = field(proxy, u"certificate", u"[B");
        Ref originalField = field(proxy, u"original", OBJECT);
        Ref originalAppField = field(proxy, u"originalApp", APPLICATION);
        Ref apkPathField = field(proxy, u"originalApkPath", STRING);
        Ref originalAppNameField = field(proxy, u"originalAppName", STRING);
        Ref signaturesField = field(PACKAGE_INFO, u"signatures", SIGNATURE_ARRAY);
        Ref signingInfoField = field(PACKAGE_INFO, u"signingInfo", u"Landroid/content/pm/SigningInfo;");
        Ref applicationInfoField = field(PACKAGE_INFO, u"applicationInfo", APPLICATION_INFO);
        Ref sourceDirField = field(APPLICATION_INFO, u"sourceDir", STRING);
        Ref publicSourceDirField = field(APPLICATION_INFO, u"publicSourceDir", STRING);
        Ref splitSourceDirsField = field(APPLICATION_INFO, u"splitSourceDirs", u"[Ljava/lang/String;");

        Ref base64Decode = method(u"Landroid/util/Base64;", u"decode", u"[B", {STRING, u"I"});
        Ref arrayNewInstance = method(u"Ljava/lang/reflect/Array;", u"newInstance", OBJECT, {OBJECT_CLASS, u"I"});
        Ref objectInit = method(OBJECT, u"<init>", u"V");
        Ref superInit = method(originalApp, u"<init>", u"V");
        Ref superAttach = method(originalApp, u"attachBaseContext", u"V", {CONTEXT});
        Ref superOnCreate = method(originalApp, u"onCreate", u"V");
        Ref objectClass = method(OBJECT, u"getClass", OBJECT_CLASS);
        Ref classForName = method(u"Ljava/lang/Class;", u"forName", OBJECT_CLASS, {STRING});
        Ref getDeclaredField = method(u"Ljava/lang/Class;", u"getDeclaredField", FIELD, {STRING});
        Ref setAccessible = method(FIELD, u"setAccessible", u"V", {u"Z"});
        Ref fieldGet = method(FIELD, u"get", OBJECT, {OBJECT});
        Ref fieldSet = method(FIELD, u"set", u"V", {OBJECT, OBJECT});
        Ref contextLoader = method(CONTEXT, u"getClassLoader", LOADER);
        Ref contextManager = method(CONTEXT, u"getPackageManager", u"Landroid/content/pm/PackageManager;");
        Ref proxyNew = method(u"Ljava/lang/reflect/Proxy;", u"newProxyInstance", OBJECT, {LOADER, u"[Ljava/lang/Class;", HANDLER_INTERFACE});
        Ref methodName = method(METHOD, u"getName", STRING);
        Ref methodInvoke = method(METHOD, u"invoke", OBJECT, {OBJECT, u"[Ljava/lang/Object;"});
        Ref stringEquals = method(STRING, u"equals", u"Z", {OBJECT});
        Ref signatureInit = method(SIGNATURE, u"<init>", u"V", {u"[B"});
        Ref fileInit = method(u"Ljava/io/File;", u"<init>", u"V", {STRING});
        Ref fileParentInit = method(u"Ljava/io/File;", u"<init>", u"V", {u"Ljava/io/File;", STRING});
        Ref fileParent = method(u"Ljava/io/File;", u"getParentFile", u"Ljava/io/File;");
        Ref cpuAbi = field(u"Landroid/os/Build;", u"CPU_ABI", STRING);
        Ref systemLoad = method(u"Ljava/lang/System;", u"load", u"V", {STRING});
        Ref fileExists = method(u"Ljava/io/File;", u"exists", u"Z");
        Ref fileMkdirs = method(u"Ljava/io/File;", u"mkdirs", u"Z");
        Ref fileAbsolute = method(u"Ljava/io/File;", u"getAbsolutePath", STRING);
        Ref contextFiles = method(CONTEXT, u"getFilesDir", u"Ljava/io/File;");
        Ref contextAssets = method(CONTEXT, u"getAssets", u"Landroid/content/res/AssetManager;");
        Ref assetOpen = method(u"Landroid/content/res/AssetManager;", u"open", u"Ljava/io/InputStream;", {STRING});
        Ref outputInit = method(u"Ljava/io/FileOutputStream;", u"<init>", u"V", {u"Ljava/io/File;"});
        Ref inputRead = method(u"Ljava/io/InputStream;", u"read", u"I", {u"[B"});
        Ref outputWrite = method(u"Ljava/io/FileOutputStream;", u"write", u"V", {u"[B", u"I", u"I"});
        Ref inputClose = method(u"Ljava/io/InputStream;", u"close", u"V");
        Ref outputClose = method(u"Ljava/io/FileOutputStream;", u"close", u"V");
        Ref classGetDeclaredMethod = method(OBJECT_CLASS, u"getDeclaredMethod", METHOD, {STRING, u"[Ljava/lang/Class;"});
        Ref loadNative = method(proxy, u"$loadNative", STRING, {CONTEXT});
        Ref logI = method(u"Landroid/util/Log;", u"i", u"I", {STRING, STRING});
        Ref logE = method(u"Landroid/util/Log;", u"e", u"I", {STRING, STRING, u"Ljava/lang/Throwable;"});
        Ref logMethod = method(proxy, u"$log", u"V", {STRING});

        Ref appInit = method(proxy, u"<init>", u"V");
        Ref appClinit = method(proxy, u"<clinit>", u"V");
        Ref attach = method(proxy, u"attachBaseContext", u"V", {CONTEXT});
        Ref install = method(proxy, u"$install", u"V", {CONTEXT});
        Ref fieldHelper = method(proxy, u"$field", FIELD, {OBJECT_CLASS, STRING});
        Ref patchPackage = method(proxy, u"$patchPackage", u"V", {PACKAGE_INFO});
        Ref patchApplication = method(proxy, u"$patchApplicationInfo", u"V", {APPLICATION_INFO});
        Ref extractApk = method(proxy, u"$extractApk", STRING, {CONTEXT});
        Ref fake = method(proxy, u"$fakeSignatures", SIGNATURE_ARRAY);
        Ref patchSigning = method(proxy, u"$patchSigningInfo", u"V", {OBJECT, SIGNATURE_ARRAY});
        Ref handlerInit = method(handler, u"<init>", u"V");
        Ref handlerInvoke = method(handler, u"invoke", OBJECT, {OBJECT, METHOD, u"[Ljava/lang/Object;"});

        dex::Class app;
        app.type = proxy; app.super = originalApp; app.flags = 0x1;
        for (auto& f : std::vector<dex::Field>{
            {certField,0xa,{}},{originalField,0xa,{}},{originalAppField,0xa,{}},{apkPathField,0xa,{}},{originalAppNameField,0xa,{}}
        }) app.staticFields.push_back(f);

        Builder constructor; constructor.add(call(superInit,0,1,0x76)); constructor.add(raw({0x0e}));
        app.direct.push_back(newMethod(appInit,0x10001,constructor.build(1,1,1)));

        Builder initializer;
        initializer.add(string(0,utf16(base64(cert)))); initializer.add(constant(1,0));
        initializer.add(call(base64Decode,0,2,0x77)); initializer.add(resultObject(0));
        initializer.add(field21(0x69,0,certField));
        initializer.add(string(0,options.applicationName)); initializer.add(field21(0x69,0,originalAppNameField));
        initializer.add(raw({0x0e}));
        app.direct.push_back(newMethod(appClinit,0x8,initializer.build(2,0,3)));

        Builder logBuilder;
        logBuilder.add(string(0, u"SigFall"));
        logBuilder.add(moveObject(1, 1));
        logBuilder.add(call(logI, 0, 2, 0x77));
        logBuilder.add(raw({0x0e}));
        app.direct.push_back(newMethod(logMethod, 0x9, logBuilder.build(2, 1, 3)));

        Builder fieldCode;
        fieldCode.add(moveObject(0,2)); fieldCode.add(moveObject(1,3));
        fieldCode.add(call(getDeclaredField,2,2,0x74)); fieldCode.add(resultObject(0));
        fieldCode.add(constant(1,1)); fieldCode.add(call(setAccessible,0,2,0x74));
        fieldCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        app.direct.push_back(newMethod(fieldHelper,0x8,fieldCode.build(4,2,3)));

        // $fakeSignatures
        Builder fakeB;
        fakeB.add(field21(0x62,0,certField));
        fakeB.add(constant(3,1));
        fakeB.add(typeOp(0x1c,2,SIGNATURE));
        fakeB.add(call(arrayNewInstance,2,2,0x77)); fakeB.add(resultObject(2));
        fakeB.add(typeOp(0x1f,2,SIGNATURE_ARRAY));
        fakeB.add(typeOp(0x22,3,SIGNATURE));
        fakeB.add(moveObject(4,0));
        fakeB.add(call(signatureInit,3,2,0x76));
        fakeB.add(constant(4,0));
        fakeB.add(three(0x4d,3,2,4));
        fakeB.add(raw({uint16_t(0x11|(2<<8)),0}));
        app.direct.push_back(newMethod(fake,0x8,fakeB.build(5,0,3)));

        // $patchSigningInfo
        Builder ps;
        ps.add(moveObject(0,4)); ps.add(moveObject(1,5));
        ps.add(moveObject(2,0)); ps.add(call(objectClass,2,1,0x74)); ps.add(resultObject(2));
        ps.add(string(3,u"mApkContentsSigners")); ps.add(call(getDeclaredField,2,2,0x74)); ps.add(resultObject(3));
        ps.add(constant(2,1)); ps.add(moveObject(4,3)); ps.add(moveInt(5,2)); ps.add(call(setAccessible,4,2,0x74));
        ps.add(moveObject(2,3)); ps.add(moveObject(3,0)); ps.add(moveObject(4,1)); ps.add(call(fieldSet,2,3,0x74));
        ps.add(moveObject(2,0)); ps.add(call(objectClass,2,1,0x74)); ps.add(resultObject(2));
        ps.add(string(3,u"mSigningCertificateHistory")); ps.add(call(getDeclaredField,2,2,0x74)); ps.add(resultObject(3));
        ps.add(constant(2,1)); ps.add(moveObject(4,3)); ps.add(moveInt(5,2)); ps.add(call(setAccessible,4,2,0x74));
        ps.add(moveObject(2,3)); ps.add(moveObject(3,0)); ps.add(moveObject(4,1)); ps.add(call(fieldSet,2,3,0x74));
        ps.add(raw({0x0e}));
        uint32_t psH=uint32_t(ps.instructions.size()); ps.add(raw({uint16_t(0x0d|(0<<8))})); ps.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchSigning,0x8,ps.build(6,2,3,psH)));

        // $patchApplicationInfo
        Builder pa;
        pa.add(moveObject(0,2));
        if (cfg.replaceApkPath || cfg.patchApplicationInfo) {
            pa.add(field21(0x62,1,apkPathField));
            uint32_t noPath=uint32_t(pa.instructions.size()); pa.add(raw({uint16_t(0x38|(1<<8)),0}));
            pa.add(field22(0x5b,1,0,sourceDirField));
            pa.add(field22(0x5b,1,0,publicSourceDirField));
            pa.instructions[noPath].target=uint32_t(pa.instructions.size());
        }
        pa.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchApplication,0x8,pa.build(3,1,2)));

        // $patchPackage
        Builder patchCode;
        patchCode.add(moveObject(0,3));
        patchCode.add(call(fake,0,0,0x77)); patchCode.add(resultObject(0));
        patchCode.add(field22(0x5b,0,3,signaturesField));
        if (cfg.replaceApkPath || cfg.patchApplicationInfo) {
            patchCode.add(field22(0x54,1,3,applicationInfoField));
            uint32_t appBranch=uint32_t(patchCode.instructions.size()); patchCode.add(raw({uint16_t(0x38|(1<<8)),0}));
            patchCode.add(call(patchApplication,1,1,0x77));
            patchCode.instructions[appBranch].target=uint32_t(patchCode.instructions.size());
        }
        if (cfg.patchSigningInfo) {
            patchCode.add(field22(0x54,1,3,signingInfoField));
            uint32_t signingBranch=uint32_t(patchCode.instructions.size()); patchCode.add(raw({uint16_t(0x38|(1<<8)),0}));
            patchCode.add(moveObject(2,0)); patchCode.add(call(patchSigning,1,2,0x77));
            patchCode.instructions[signingBranch].target=uint32_t(patchCode.instructions.size());
        }
        patchCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(patchPackage,0x8,patchCode.build(4,1,3)));

        // $install PM proxy
        Builder installCode;
        installCode.add(moveObject(0,6));
        installCode.add(string(0,u"android.app.ActivityThread"));
        installCode.add(call(classForName,0,1,0x77)); installCode.add(resultObject(0));
        installCode.add(moveObject(1,0)); installCode.add(string(2,u"sPackageManager"));
        installCode.add(call(fieldHelper,1,2,0x77)); installCode.add(resultObject(1));
        installCode.add(constant(2,0)); installCode.add(call(fieldGet,1,2,0x74)); installCode.add(resultObject(0));
        installCode.add(field21(0x69,0,originalField));
        installCode.add(call(contextLoader,6,1,0x74)); installCode.add(resultObject(2));
        installCode.add(typeOp(0x1c,3,OBJECT_CLASS)); installCode.add(constant(4,1));
        installCode.add(call(arrayNewInstance,3,2,0x77)); installCode.add(resultObject(3));
        installCode.add(typeOp(0x1f,3,u"[Ljava/lang/Class;"));
        installCode.add(call(objectClass,0,1,0x74)); installCode.add(resultObject(4));
        installCode.add(constant(5,0)); installCode.add(three(0x4d,4,3,5));
        installCode.add(typeOp(0x22,4,handler)); installCode.add(call(handlerInit,4,1,0x76));
        installCode.add(call(proxyNew,2,3,0x77)); installCode.add(resultObject(2));
        installCode.add(moveObject(3,2)); installCode.add(constant(2,0)); installCode.add(call(fieldSet,1,3,0x74));
        installCode.add(call(contextManager,6,1,0x74)); installCode.add(resultObject(5));
        installCode.add(call(objectClass,5,1,0x74)); installCode.add(resultObject(0));
        installCode.add(string(1,u"mPM")); installCode.add(call(fieldHelper,0,2,0x77)); installCode.add(resultObject(0));
        installCode.add(moveObject(1,5)); installCode.add(moveObject(2,3)); installCode.add(call(fieldSet,0,3,0x74));
        installCode.add(raw({0x0e}));
        uint32_t installH=uint32_t(installCode.instructions.size());
        installCode.add(raw({uint16_t(0x0d|(0<<8))}));
        installCode.add(string(1,u"SigFall"));
        installCode.add(string(2,u"pm proxy install failed"));
        installCode.add(moveObject(3,0));
        installCode.add(call(logE,1,3,0x77));
        installCode.add(raw({0x0e}));
        app.direct.push_back(newMethod(install,0x8,installCode.build(7,1,3,installH)));

        // $extractApk
        Builder ex;
        ex.add(moveObject(0,11)); // v0 = ctx (ins=1, regs=12 -> v11)
        ex.add(field21(0x62,1,apkPathField)); // v1 = apkPath
        uint32_t exOk=uint32_t(ex.instructions.size()); ex.add(raw({uint16_t(0x39|(1<<8)),0})); // if-nez v1
        ex.add(raw({uint16_t(0x11|(1<<8)),0})); // return-object v1
        ex.instructions[exOk].target=uint32_t(ex.instructions.size());
        ex.add(call(contextFiles,0,1,0x74)); ex.add(resultObject(1)); // v1 = filesDir
        ex.add(string(2,u"fancy"));
        ex.add(typeOp(0x22,3,u"Ljava/io/File;")); ex.add(moveObject(4,1)); ex.add(moveObject(5,2));
        ex.add(call(fileParentInit,3,3,0x76)); // v3 = new File(filesDir,"fancy")
        ex.add(call(fileMkdirs,3,1,0x74)); ex.add(resultInt(9));
        ex.add(string(4,u"origin.apk"));
        ex.add(typeOp(0x22,5,u"Ljava/io/File;")); ex.add(moveObject(6,3)); ex.add(moveObject(7,4));
        ex.add(call(fileParentInit,5,3,0x76)); // v5 = new File(fancyDir,"origin.apk")
        ex.add(call(fileExists,5,1,0x74)); ex.add(resultInt(9));
        uint32_t needCopy=uint32_t(ex.instructions.size()); ex.add(raw({uint16_t(0x38|(9<<8)),0})); // if-eqz v9
        ex.add(call(fileAbsolute,5,1,0x74)); ex.add(resultObject(9)); ex.add(field21(0x69,9,apkPathField)); ex.add(raw({uint16_t(0x11|(9<<8)),0}));
        ex.instructions[needCopy].target=uint32_t(ex.instructions.size());
        if (doEmbed) {
            ex.add(call(contextAssets,0,1,0x74)); ex.add(resultObject(2)); // v2 = assets
            ex.add(string(3,options.originalApkAsset));
            ex.add(call(assetOpen,2,2,0x74)); ex.add(resultObject(4)); // v4 = inputStream
            ex.add(typeOp(0x22,6,u"Ljava/io/FileOutputStream;")); ex.add(moveObject(7,5)); ex.add(call(outputInit,6,2,0x76)); // v6 = out(file v5)
            ex.add(constant(7,4096)); ex.add(arrayOp(0x23,7,7,u"[B")); // v7 = buf
            ex.add(constant(8,0)); // v8 = off
            uint32_t loop=uint32_t(ex.instructions.size());
            ex.add(moveObject(0,4)); ex.add(moveObject(1,7)); ex.add(call(inputRead,0,2,0x74)); ex.add(resultInt(0)); // v0=read(v4,v7)
            uint32_t done=uint32_t(ex.instructions.size()); ex.add(raw({uint16_t(0x3a|(0<<8)),0})); // if-gtz v0
            Instruction w; w.op=0x6e; w.ref=outputWrite; w.units={uint16_t(0x6e|(4<<12)),0,uint16_t(6|(7<<4)|(8<<8)|(0<<12))}; w.oldPc=int64_t(ex.instructions.size()); ex.instructions.push_back(w); // write(v6,v7,v8,v0)
            { uint32_t g=uint32_t(ex.instructions.size()); ex.add(raw({uint16_t(0x28),0})); ex.instructions[g].target=loop; ex.instructions[g].op=40; }
            ex.instructions[done].target=uint32_t(ex.instructions.size());
            ex.add(call(inputClose,4,1,0x74));
            ex.add(call(outputClose,6,1,0x74));
            ex.add(call(fileAbsolute,5,1,0x74)); ex.add(resultObject(9)); ex.add(field21(0x69,9,apkPathField));
            ex.add(raw({uint16_t(0x11|(9<<8)),0}));
        } else {
            ex.add(raw({uint16_t(0x12|(9<<8)),0})); ex.add(raw({uint16_t(0x11|(9<<8)),0}));
        }
        uint32_t exH=uint32_t(ex.instructions.size()); ex.add(raw({uint16_t(0x0d|(0<<8))})); ex.add(raw({uint16_t(0x12|(0<<8)),0})); ex.add(raw({uint16_t(0x11|(0<<8)),0}));
        app.direct.push_back(newMethod(extractApk,0x8,ex.build(12,1,5,exH)));

        // $loadNative
        Builder nat;
        nat.add(field21(0x62,0,cpuAbi)); // v0 = Build.CPU_ABI
        nat.add(string(1,u"arm64-v8a"));
        nat.add(call(stringEquals,0,2,0x74)); nat.add(resultInt(1));
        uint32_t natArm64 = uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x38|(1<<8)),0}));
        nat.add(string(2,u"fancy/lib/arm64.so")); nat.add(string(3,u"libsigfall")); nat.add(string(4,u"arm64.so"));
        uint32_t natChooseEnd = uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x28),0}));
        nat.instructions[natArm64].target=uint32_t(nat.instructions.size());
        nat.add(string(1,u"armeabi-v7a"));
        nat.add(call(stringEquals,0,2,0x74)); nat.add(resultInt(1));
        uint32_t natArm = uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x38|(1<<8)),0}));
        nat.add(string(2,u"fancy/lib/arm.so")); nat.add(string(3,u"libsigfall")); nat.add(string(4,u"arm.so"));
        nat.instructions[natChooseEnd].target=uint32_t(nat.instructions.size());
        uint32_t natUnsupportedSkip = uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x28),0}));
        nat.instructions[natArm].target=uint32_t(nat.instructions.size());
        nat.add(raw({uint16_t(0x12|(0<<8)),0})); nat.add(raw({uint16_t(0x11|(0<<8)),0}));
        nat.instructions[natUnsupportedSkip].target=uint32_t(nat.instructions.size());
        nat.add(call(contextFiles,11,1,0x74)); nat.add(resultObject(5)); // v5 = filesDir
        nat.add(typeOp(0x22,6,u"Ljava/io/File;")); nat.add(moveObject(7,5)); nat.add(moveObject(8,3));
        nat.add(call(fileParentInit,6,3,0x76)); // v6 = filesDir/libsigfall
        nat.add(typeOp(0x22,7,u"Ljava/io/File;")); nat.add(moveObject(8,6)); nat.add(moveObject(9,4));
        nat.add(call(fileParentInit,7,3,0x76)); // v7 = filesDir/libsigfall/<abi>.so
        nat.add(call(fileExists,7,1,0x74)); nat.add(resultInt(8));
        uint32_t natCopy = uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x38|(8<<8)),0}));
        uint32_t natSkip = uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x28),0}));
        nat.instructions[natCopy].target=uint32_t(nat.instructions.size());
        nat.add(call(fileParent,7,1,0x74)); nat.add(resultObject(8));
        nat.add(call(fileMkdirs,8,1,0x74)); nat.add(resultInt(8));
        nat.add(call(contextAssets,11,1,0x74)); nat.add(resultObject(8));
        nat.add(moveObject(9,2)); nat.add(call(assetOpen,8,2,0x74)); nat.add(resultObject(2)); // v2 = inputStream
        nat.add(typeOp(0x22,10,u"Ljava/io/FileOutputStream;")); nat.add(moveObject(8,7));
        nat.add(raw({uint16_t(0x70|(2<<8)),0,uint16_t(10|(8<<4))},outputInit)); // v10 = outputStream
        nat.add(constant(0,4096)); nat.add(arrayOp(0x23,0,0,u"[B")); // v0 = buf
        nat.add(constant(1,0)); // v1 = off
        uint32_t natLoop=uint32_t(nat.instructions.size());
        nat.add(moveObject(8,2)); nat.add(moveObject(9,0));
        nat.add(call(inputRead,8,2,0x74)); nat.add(resultInt(8));
        uint32_t natDone=uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x3d|(8<<8)),0}));
        Instruction nw; nw.op=0x6e; nw.ref=outputWrite; nw.units={uint16_t(0x6e|(4<<12)),0,uint16_t(10|(0<<4)|(1<<8)|(8<<12))}; nw.oldPc=int64_t(nat.instructions.size()); nat.instructions.push_back(nw);
        { uint32_t g=uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x28),0})); nat.instructions[g].target=natLoop; nat.instructions[g].op=40; }
        nat.instructions[natDone].target=uint32_t(nat.instructions.size());
        nat.add(call(inputClose,2,1,0x74));
        nat.add(call(outputClose,10,1,0x74));
        nat.instructions[natSkip].target=uint32_t(nat.instructions.size());
        nat.add(call(fileAbsolute,7,1,0x74)); nat.add(resultObject(0));
        nat.add(call(systemLoad,0,1,0x77));
        nat.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t natH=uint32_t(nat.instructions.size()); nat.add(raw({uint16_t(0x0d|(0<<8)),0}));
        nat.add(raw({uint16_t(0x12|(0<<8)),0})); nat.add(raw({uint16_t(0x11|(0<<8)),0}));
        app.direct.push_back(newMethod(loadNative,0x8,nat.build(12,1,6,natH)));

        // attachBaseContext
        Builder attachCode;
        // ins=2: this=v9, base=v10 (regs=11)
        attachCode.add(moveObject(0,9)); attachCode.add(moveObject(1,10));
        if (doEmbed) { attachCode.add(call(extractApk,0,1,0x77)); attachCode.add(resultObject(2)); attachCode.add(moveObject(0,9)); attachCode.add(moveObject(1,10)); }
        attachCode.add(moveObject(0,9));
        attachCode.add(call(loadNative,0,1,0x77)); attachCode.add(resultObject(0));
        if (cfg.pmProxy) {
            attachCode.add(moveObject(0,9)); attachCode.add(call(install,0,1,0x77));
            attachCode.add(string(0,u"pm proxy installed"));
            attachCode.add(call(logMethod,0,1,0x77));
        }
        attachCode.add(moveObject(0,9)); attachCode.add(moveObject(1,10));
        attachCode.add(call(superAttach,0,2,0x75));
        attachCode.add(raw({0x0e}));
        uint32_t attachH=uint32_t(attachCode.instructions.size()); attachCode.add(raw({uint16_t(0x0d|(0<<8))})); attachCode.add(raw({0x0e}));
        app.virtuals.push_back(newMethod(attach,0x1,attachCode.build(11,2,4,attachH)));

        // onCreate -> original application
        if (cfg.delegateOriginalApplication) {
            Builder oc;
            oc.add(moveObject(0,1)); oc.add(call(superOnCreate,0,1,0x75));
            oc.add(raw({0x0e}));
            uint32_t ocH=uint32_t(oc.instructions.size()); oc.add(raw({uint16_t(0x0d|(0<<8))})); oc.add(raw({0x0e}));
            app.virtuals.push_back(newMethod(method(proxy,u"onCreate",u"V"),0x1,oc.build(2,1,1,ocH)));
        }

        // InvocationHandler for PM
        dex::Class proxyClass;
        proxyClass.type = handler; proxyClass.super = OBJECT; proxyClass.flags = 0x1;
        proxyClass.interfaces.push_back(HANDLER_INTERFACE);
        Builder hInit; hInit.add(call(objectInit,0,1,0x76)); hInit.add(raw({0x0e}));
        proxyClass.direct.push_back(newMethod(handlerInit,0x10001,hInit.build(1,1,1)));
        Builder invokeCode;
        invokeCode.add(field21(0x62,1,originalField));
        invokeCode.add(moveObject(2,6));
        invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2));
        invokeCode.add(string(3,u"getPackageInfo"));
        invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
        uint32_t bNotPkg=uint32_t(invokeCode.instructions.size()); invokeCode.add(raw({uint16_t(0x38|(3<<8)),0}));
        invokeCode.add(string(0,u"getPackageInfo intercepted"));
        invokeCode.add(call(logMethod,0,1,0x77));
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(typeOp(0x1f,0,PACKAGE_INFO)); invokeCode.add(call(patchPackage,0,1,0x77));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        uint32_t notPkg=uint32_t(invokeCode.instructions.size()); invokeCode.instructions[bNotPkg].target=notPkg;
        auto hookPackageInfo = [&](const char16_t* name) {
            invokeCode.add(moveObject(2,6)); invokeCode.add(call(methodName,2,1,0x74)); invokeCode.add(resultObject(2));
            invokeCode.add(string(3, Text(name)));
            invokeCode.add(call(stringEquals,3,2,0x74)); invokeCode.add(resultInt(3));
            uint32_t bNot=uint32_t(invokeCode.instructions.size()); invokeCode.add(raw({uint16_t(0x38|(3<<8)),0}));
            invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
            invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
            invokeCode.add(typeOp(0x1f,0,PACKAGE_INFO)); invokeCode.add(call(patchPackage,0,1,0x77));
            invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
            invokeCode.instructions[bNot].target=uint32_t(invokeCode.instructions.size());
        };
        hookPackageInfo(u"getPackageArchiveInfo");
        hookPackageInfo(u"generatePackageInfo");
        invokeCode.add(moveObject(0,1)); invokeCode.add(moveObject(2,6)); invokeCode.add(moveObject(3,7));
        invokeCode.add(call(methodInvoke,0,3,0x74)); invokeCode.add(resultObject(0));
        invokeCode.add(raw({uint16_t(0x11|(0<<8)),0}));
        proxyClass.virtuals.push_back(newMethod(handlerInvoke,0x1,invokeCode.build(8,4,4)));

        // ProxyComponentFactory - simple delegate
        dex::Class fac;
        fac.type=factory; fac.super=u"Landroid/app/AppComponentFactory;"; fac.flags=0x1;
        Builder facInit; facInit.add(call(method(u"Landroid/app/AppComponentFactory;",u"<init>",u"V"),0,1,0x76)); facInit.add(raw({0x0e}));
        fac.direct.push_back(newMethod(method(factory,u"<init>",u"V"),0x10001,facInit.build(1,1,1)));
        // instantiateApplication
        Builder ia;
        // ins=3: this=v3, cl=v4, className=v5
        ia.add(string(0,helperName));
        ia.add(moveObject(1,5));
        ia.add(call(stringEquals,0,2,0x74)); ia.add(resultInt(0));
        uint32_t notProxy=uint32_t(ia.instructions.size()); ia.add(raw({uint16_t(0x38|(0<<8)),0}));
        ia.add(typeOp(0x22,0,proxy));
        ia.add(call(appInit,0,1,0x76));
        ia.add(raw({uint16_t(0x11|(0<<8)),0}));
        ia.instructions[notProxy].target=uint32_t(ia.instructions.size());
        ia.add(moveObject(0,3)); ia.add(moveObject(1,4)); ia.add(moveObject(2,5));
        ia.add(call(method(u"Landroid/app/AppComponentFactory;",u"instantiateApplication",APPLICATION,{LOADER,STRING}),0,3,0x75)); ia.add(resultObject(0));
        ia.add(typeOp(0x1f,0,APPLICATION));
        ia.add(raw({uint16_t(0x11|(0<<8)),0}));
        fac.virtuals.push_back(newMethod(method(factory,u"instantiateApplication",APPLICATION,{LOADER,STRING}),0x1,ia.build(6,3,3)));

        dex::Model model; model.classes.push_back(app); model.classes.push_back(proxyClass); model.classes.push_back(fac);
        SignatureResult result;
        result.bytes = dex::write(model);
        validateDex(result.bytes);
        result.report.classes = 3;
        result.report.methods = uint32_t(10 + app.direct.size() + app.virtuals.size());
        result.report.sites = cert.size();
        result.changed = true;
        return result;
    }
}
