#pragma once
#include "bytes.hpp"
#include <unordered_map>
namespace dexpack::dex {
    enum class Kind {
        None, String, Type, Proto, Field, Method, Handle, Callsite
    };
    struct Symbol;
    using Ref = std::shared_ptr<Symbol>;
    struct Symbol {
        Kind kind = Kind::None;
        Text text, owner, type;
        std::vector<Text> params;
        Ref proto;
        uint32_t index = 0;
    };
    Ref textRef(Kind kind, const Text& value);
    Ref prototype(const Text& result, const std::vector<Text>& parameters = {});
    Ref method(const Text& owner, const Text& name, const Text& result, const std::vector<Text>& parameters = {});
    Ref field(const Text& owner, const Text& name, const Text& type);
    Text key(const Ref& ref);
    Text shorty(const Ref& proto);
    struct Annotation;
    struct Value {
        uint8_t type = 30, arg = 0;
        Bytes raw;
        Ref ref;
        std::vector<Value> items;
        std::shared_ptr<Annotation> annotation;
    };
    struct Annotation {
        Text type;
        std::vector<std::pair<Text, Value>> items;
        uint8_t visibility = 0;
    };
    using Ann = std::shared_ptr<Annotation>;
    using AnnSet = std::shared_ptr<std::vector<Ann>>;
    using AnnParams = std::shared_ptr<std::vector<AnnSet>>;
    struct Directory {
        AnnSet cls;
        std::vector<std::pair<Ref,AnnSet>> fields, methods;
        std::vector<std::pair<Ref,AnnParams>> params;
    };
    struct Instruction {
        int64_t oldPc = -1, target = -1;
        uint32_t pc = 0, width = 0;
        uint8_t op = 0;
        uint16_t payload = 0;
        std::vector<uint16_t> units;
        Ref ref, proto;
        std::vector<uint32_t> cases;
        bool movedStatic = false;
    };
    struct Handler {
        std::vector<std::pair<Text,uint32_t>> types;
        std::optional<uint32_t> catchAll;
    };
    struct Try {
        uint32_t start = 0, length = 0;
        std::shared_ptr<Handler> handler;
    };
    struct DebugEvent {
        uint8_t op = 0;
        uint32_t pc = 0, reg = 0;
        int32_t line = 0;
        std::optional<Text> name, type, sig, file;
    };
    struct Debug {
        uint32_t line = 0;
        std::vector<std::optional<Text>> params;
        std::vector<DebugEvent> events;
    };
    struct Code {
        uint32_t registers = 0, ins = 0, outs = 0, oldSize = 0;
        std::vector<Instruction> instructions;
        std::vector<Try> tries;
        std::shared_ptr<Debug> debug;
    };
    struct Field {
        Ref ref;
        uint32_t flags = 0;
        std::optional<Value> value;
    };
    struct Method {
        Ref ref;
        uint32_t flags = 0;
        std::shared_ptr<Code> code;
    };
    struct Class {
        Text type;
        uint32_t flags = 0;
        std::optional<Text> super, source;
        std::vector<Text> interfaces;
        std::shared_ptr<Directory> annotations;
        std::vector<Field> staticFields, instanceFields;
        std::vector<std::shared_ptr<Method>> direct, virtuals;
    };
    struct Handle {
        uint16_t kind = 0;
        Ref ref;
    };
    struct Model {
        std::string version = "035";
        std::vector<Class> classes;
        std::vector<Handle> handles;
        std::vector<std::vector<Value>> callsites;
    };
    Model read(const Bytes& bytes, bool skipDebug = false, bool skipAnnotations = false);
    std::vector<Text> classNames(const Bytes& bytes);
    Bytes write(const Model& model);
    void rename(Model& model, const Text& before, const Text& after);
    Instruction raw(std::initializer_list<uint16_t> units, Ref ref = {});
    Instruction constant(uint16_t reg, int32_t value);
    Instruction string(uint16_t reg, const Text& text);
    Instruction invoke(const Ref& ref, uint16_t base, uint8_t count = 1);
    std::shared_ptr<Code> newCode(std::vector<Instruction> instructions, uint32_t registers, uint32_t ins = 0, uint32_t outs = 1);
    std::shared_ptr<Method> newMethod(const Ref& ref, uint32_t flags, std::shared_ptr<Code> code);
}
