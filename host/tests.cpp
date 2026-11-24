#include "engine.hpp"
#include "fancy_payloads.hpp"
#include <iostream>
using namespace dexpack;
using namespace dexpack::dex;
static void expect(bool value, const char* message) {
    require(value, message);
}
static Model fixture(uint32_t registers, bool incomingWide = false) {
    Model m;
    Class c;
    c.type = u"Ltest/Strings;";
    c.flags = 0x11;
    c.super = u"Ljava/lang/Object;";
    auto literal = string(0, u"Hello native 世界");
    literal.oldPc = 0;
    auto ret = raw( {
        17
    });
    ret.oldPc = 3;
    auto code = newCode( {
        literal, ret
    }, registers, incomingWide ? 2 : 0);
    code->oldSize = 4;
    c.direct.push_back(newMethod(method(c.type, u"value", u"Ljava/lang/String;", incomingWide ? std::vector<Text> {
        u"J"
    }
    : std::vector<Text>{}), 9, code));
    m.classes.push_back(c);
    return m;
}
static void crypto() {
    expect(hex(md5(ascii("abc"))) == "900150983cd24fb0d6963f7d28e17f72", "MD5 vector failed");
    auto b = ascii("abc");
    expect(hex(sha1(b.data(), b.size())) == "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1 vector failed");
    expect(encryptString(u"abc", u"Fallen") == u"Fallen-ddf7a7bd692d7b807855618457fdc657", "Reference AES vector failed");
    Text t = u"A\0";
    t.push_back(0xd83d);
    t.push_back(0xde42);
    t += u"世界";
    Writer w;
    mutfWrite(w, t);
    Reader r(w.b);
    expect(mutfRead(r) == t, "DEX MUTF-8 roundtrip failed");
    expect(utf16(utf8(t)) == t, "UTF-8 roundtrip failed");
    expect(!validText(Text(1, 0xd800)), "Unpaired surrogate accepted");
}
static void frames() {
    for (int version : {
        1, 2
    }) for (uint32_t registers : {
        2u, 257u, 65535u
    }) {
        auto input = write(fixture(registers));
        StringContext ctx("0123456789abcdef");
        ctx.millis = [] {
            return int64_t(1700000000000);
        };
        auto result = transformStrings(input, version, {
            u"Ltest/Strings;"
        }, ctx);
        expect(result.report.literals == 1, "String was not transformed");
        auto model = read(result.bytes);
        auto target = model.classes[0].direct[0];
        for (const auto& candidate : model.classes[0].direct) if (candidate->ref->text == u"value") target = candidate;
        expect(target->code->registers == (registers < 254 ? registers + 3 : registers), "Register frame changed unexpectedly");
        expect(result.report.highRegisterSites == (registers > 254 ? 1u : 0u), "High-register bridge missing");
        expect(stringHelper(version, ctx).classes.size() == 1, "Runtime helper missing");
        validateDex(result.bytes);
    }
    auto input = write(fixture(4, true));
    StringContext ctx("wideparameters00");
    auto result = transformStrings(input, 1, {
        u"Ltest/Strings;"
    }, ctx);
    auto method = read(result.bytes).classes[0].direct[0];
    expect(method->code->registers == 9, "Wide incoming frame size");
    expect(method->code->instructions[0].units == std::vector<uint16_t>( {
        0x0205, 7
    }), "Wide parameter copy is incorrect");
}
static void branchesAndExceptions() {
    auto m = fixture(2);
    auto& code = *m.classes[0].direct[0]->code;
    Instruction conditional = raw( {
        0x38, 0
    });
    conditional.oldPc = 0;
    conditional.target = 4;
    auto original = string(0, u"x");
    original.oldPc = 2;
    auto end = raw( {
        17
    });
    end.oldPc = 4;
    code.instructions = {
        conditional, original
    };
    for (int n = 0; n < 40000; n++) code.instructions.push_back(raw( {
        0
    }));
    code.instructions.push_back(end);
    code.oldSize = 5;
    auto handler = std::make_shared<Handler>();
    handler->catchAll = 4;
    code.tries.push_back( {
        2, 2, handler
    });
    auto out = read(write(m));
    auto result = out.classes[0].direct[0]->code;
    expect(result->instructions[0].op == 0x39 && result->instructions[1].op == 42, "Long conditional branch was not expanded");
    expect(result->tries.size() == 1 && result->tries[0].handler->catchAll.has_value(), "Exception handler lost");
}
static void staticAndInterfaces() {
    for (int version : {
        1, 2
    }) {
        auto m = fixture(2);
        auto& c = m.classes[0];
        Value value;
        value.type = 23;
        value.ref = textRef(Kind::String, u"constant");
        c.staticFields.push_back( {
            field(c.type, u"VALUE", u"Ljava/lang/String;"), 0x19, value
        });
        auto input = write(m);
        StringContext ctx;
        auto result = transformStrings(input, version, {
            c.type
        }, ctx);
        expect(result.report.staticFields == 1, "Static string was not moved");
        auto out = read(result.bytes);
        expect(out.classes[0].staticFields[0].value.has_value(), "Static field values missing");
        c.flags |= 0x200;
        input = write(m);
        StringContext interfaceContext;
        auto preserved = transformStrings(input, version, {
            c.type
        }, interfaceContext);
        expect(preserved.report.staticFields == 0, "Interface constant was moved");
        if (version == 2) expect(preserved.bytes == input, "V2 interface code changed");
    }
}
static void sharedCodeAndMetadata() {
    auto m = fixture(2);
    auto second = m.classes[0];
    second.type = u"Ltest/Other;";
    second.direct = {
        newMethod(method(second.type, u"other", u"Ljava/lang/String;"), 9, m.classes[0].direct[0]->code)
    };
    m.classes.push_back(second);
    auto annotation = std::make_shared<Annotation>();
    annotation->type = u"Ltest/Annotation;";
    Value text;
    text.type = 23;
    text.ref = textRef(Kind::String, u"metadata");
    annotation->items.emplace_back(u"name", text);
    m.classes[0].annotations = std::make_shared<Directory>();
    m.classes[0].annotations->cls = std::make_shared<std::vector<Ann>>(std::initializer_list<Ann> {
        annotation
    });
    auto input = write(m);
    StringContext ctx;
    auto changed = read(transformStrings(input, 1, {
        u"Ltest/Strings;"
    }, ctx).bytes);
    const Class* other = nullptr;
    const Class* selected = nullptr;
    for (const auto& c : changed.classes) {
        if (c.type == u"Ltest/Other;") other = &c;
        else selected = &c;
    }
    expect(other && other->direct[0]->code->registers == 2, "Shared code item mutated unselected class");
    expect(other->direct[0]->code->instructions[0].ref->text == u"Hello native 世界", "Unselected plaintext changed");
    expect(selected && selected->annotations->cls->at(0)->items[0].second.ref->text == u"metadata", "Annotation string changed");
}
static void referenceTemplates() {
    const char* hashes[]={"4a68f496539cb5a1a948e6945c781872a3f2e1a7","1c836cf61b4d44e8c371765b93a2b65b137dc301"};
    for(int version:{1,2}) {
        const auto bytes=version==1?payload::v1():payload::v2();
        expect(hex(sha1(bytes.data(),bytes.size()))==hashes[version-1],"Original reference helper bytes changed");
        StringContext ctx("collision");
        ctx.prepare(version);
        const auto original=read(bytes);
        expect(ctx.owner==original.classes[0].type,"Reference helper class name changed");
        expect(ctx.decoder->proto->params.size()==size_t(version==1?2:1),"Wrong reference decoder signature");
        expect(ctx.decoder->text!=u"decodeStr","Original decoder name was normalized");
        expect(original.classes[0].direct.size()==11,"Missing reference helper methods");
        expect(original.classes[0].staticFields.size()==size_t(version==1?2:3),"Missing reference helper fields");
        expect(original.classes[0].source==(version==1?u"StringEncryptionHelper.java":u"StringEncryptionProHelper.java"),"Reference source name changed");
        expect(stringHelperDex(version,ctx)==bytes,"Unmodified helper DEX was rebuilt");
        auto occupied=std::set<Text>{ctx.owner,ctx.owner.substr(0,ctx.owner.size()-1)+u"$collision;"};
        StringContext collided("collision");
        collided.prepare(version,occupied);
        expect(!occupied.count(collided.owner),"Helper collision was not resolved");
        expect(collided.decoder->owner==collided.owner,"Decoder still targets occupied class");
        auto renamed=read(stringHelperDex(version,collided));
        rename(renamed,collided.owner,ctx.owner);
        expect(write(renamed)==write(original),"Collision rename changed reference helper behavior");
        auto transformed=read(transformStrings(write(fixture(2)),version,{u"Ltest/Strings;"},collided).bytes);
        size_t calls=0;
        for(const auto&c:transformed.classes)for(const auto&m:c.direct)if(m->code)for(const auto&i:m->code->instructions) {
            if(i.ref&&i.ref->kind==Kind::Method&&i.ref->owner==collided.owner) {
                expect(key(i.ref)==key(collided.decoder),"Generated call misses reference decoder");
                ++calls;
            }
        }
        expect(calls==1,"Reference decoder was not invoked");
        auto merged=fixture(2);
        const auto helper=stringHelper(version,collided);
        merged.classes.insert(merged.classes.end(),helper.classes.begin(),helper.classes.end());
        expect(read(write(merged)).classes.size()==2,"Primary DEX helper merge failed");
        bool rejected=false;
        try {collided.prepare(3-version);}catch(const std::exception&){rejected=true;}
        expect(rejected,"Mixed V1/V2 context was accepted");
    }
}
static void signatureKiller() {
    Archive apk("../sample application.apk");
    SignatureOptions options;
    options.className = u"Ltest/SigHelper;";
    auto result = killSignatures(apk, options);
    expect(result.changed, "Signature helper was not generated");
    expect(result.report.classes == 1, "Unexpected number of generated classes");
    expect(result.report.methods == 8, "Unexpected number of generated methods");
    expect(result.report.sites > 0, "Certificate was not embedded");
    validateDex(result.bytes);
    const auto out = read(result.bytes);
    bool helperFound = false;
    for (const auto& c : out.classes) if (c.type == options.className) helperFound = true;
    expect(helperFound, "Generated helper class is missing");
}
static void nativeHelper() {
    auto model = read(fancy::referenceDex());
    expect(model.classes.size() > 50, "Reference native helper is missing classes");
    const Text before = u"Lorg/clipbox/player/ClipBoxApplication;";
    const Text after = u"Lorg/test/TestApplication;";
    rename(model, before, after);
    auto bytes = write(model);
    validateDex(bytes);
    const auto out = read(bytes);
    expect(out.classes.size() == model.classes.size(), "Native helper lost classes after patch");
    bool target = false, legacy = false;
    for (const auto& c : out.classes) for (const auto& m : c.direct) {
        if (!m->code) continue;
        for (const auto& i : m->code->instructions) {
            if (!i.ref) continue;
            target |= i.ref->text == after || i.ref->owner == after;
            legacy |= i.ref->text == before || i.ref->owner == before;
        }
    }
    expect(target, "Target application class was not patched into native helper");
    expect(!legacy, "ClipBox application class remained in native helper");
}
int main() {
    try {
        crypto();
        frames();
        branchesAndExceptions();
        staticAndInterfaces();
        sharedCodeAndMetadata();
        referenceTemplates();
        signatureKiller();
        nativeHelper();
        std::cout << "8 native test groups passed\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
