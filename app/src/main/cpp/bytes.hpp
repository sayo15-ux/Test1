#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
namespace dexpack {
    using Bytes = std::vector<uint8_t>;
    using Text = std::u16string;
    constexpr uint32_t NONE = 0xffffffffu;
    inline void require(bool value, const std::string& message) {
        if (!value) throw std::runtime_error(message);
    }
    inline uint32_t narrow(uint64_t n) {
        require(n < NONE, "The file exceeds the 32-bit DEX/ZIP format.");
        return static_cast<uint32_t>(n);
    }
    struct Reader {
        const Bytes& b;
        size_t p;
        explicit Reader(const Bytes& bytes, size_t offset = 0) : b(bytes), p(offset) {}
        void need(size_t n) const {
            require(p <= b.size() && n <= b.size() - p, "Truncated binary data.");
        }
        uint8_t u8() {
            need(1);
            return b[p++];
        }
        uint16_t u16() {
            auto a = u8();
            return uint16_t(a | uint16_t(u8()) << 8);
        }
        uint32_t u32() {
            auto a = u16();
            return uint32_t(a) | uint32_t(u16()) << 16;
        }
        uint32_t u() {
            uint32_t n = 0;
            for (unsigned i = 0; i < 5; ++i) {
                auto v = u8();
                require(i != 4 || v < 16, "Invalid ULEB128.");
                n |= uint32_t(v & 127) << (7 * i);
                if (!(v & 128)) return n;
            }
            throw std::runtime_error("Invalid ULEB128.");
        }
        int32_t s() {
            uint32_t n = 0;
            unsigned shift = 0;
            uint8_t v;
            do {
                require(shift < 35, "Invalid SLEB128.");
                v = u8();
                n |= uint32_t(v & 127) << shift;
                shift += 7;
            }
            while (v & 128);
            if (shift < 32 && (v & 64)) n |= ~uint32_t(0) << shift;
            return static_cast<int32_t>(n);
        }
        uint32_t count(uint32_t n) const {
            require(n <= b.size(), "Invalid item count.");
            return n;
        }
        Bytes take(size_t n) {
            need(n);
            Bytes out(b.begin() + p, b.begin() + p + n);
            p += n;
            return out;
        }
    };
    struct Writer {
        Bytes b;
        size_t base = 0;
        explicit Writer(size_t start = 0) : base(start) {}     uint32_t size() const {
            return narrow(uint64_t(base) + b.size());
        }
        Writer& bytes(const Bytes& v) {
            b.insert(b.end(), v.begin(), v.end());
            return *this;
        }
        Writer& u8(uint32_t n) {
            b.push_back(uint8_t(n));
            return *this;
        }
        Writer& u16(uint32_t n) {
            return u8(n).u8(n >> 8);
        }
        Writer& u32(uint32_t n) {
            return u16(n).u16(n >> 16);
        }
        Writer& u(uint32_t n) {
            do {
                auto v = n & 127;
                n >>= 7;
                u8(v | (n ? 128 : 0));
            }
            while (n);
            return *this;
        }
        Writer& s(int32_t n) {
            for (;;) {
                auto v = uint32_t(n) & 127;
                n >>= 7;
                bool more = !((n == 0 && !(v & 64)) || (n == -1 && (v & 64)));
                u8(v | (more ? 128 : 0));
                if (!more) return *this;
            }
        }
        Writer& align(size_t alignment = 4) {
            while ((base + b.size()) % alignment) u8(0);
            return *this;
        }
    };
    inline uint16_t get16(const Bytes& b, size_t p) {
        return Reader(b, p).u16();
    }
    inline uint32_t get32(const Bytes& b, size_t p) {
        return Reader(b, p).u32();
    }
    inline void put16(Bytes& b, size_t p, uint32_t v) {
        require(p <= b.size() && b.size() - p >= 2, "Invalid binary write.");
        b[p] = uint8_t(v);
        b[p+1] = uint8_t(v >> 8);
    }
    inline void put32(Bytes& b, size_t p, uint32_t v) {
        put16(b, p, v);
        put16(b, p+2, v >> 16);
    }
    inline Bytes slice(const Bytes& b, size_t p, size_t n) {
        return Reader(b, p).take(n);
    }
    inline Bytes ascii(const std::string& s) {
        return Bytes(s.begin(), s.end());
    }
    inline std::string hex(const Bytes& b) {
        std::string s;
        s.reserve(b.size() * 2);
        for (auto v : b) {
            s += "0123456789abcdef"[v >> 4];
            s += "0123456789abcdef"[v & 15];
        }
        return s;
    }
    std::string utf8(const Text& s);
    Text utf16(const std::string& s);
    bool validText(const Text& s);
    Bytes from64(const std::string& s);
    Bytes readFile(const std::string& path);
    void writeFile(const std::string& path, const Bytes& bytes);
    Text mutfRead(Reader& r);
    void mutfWrite(Writer& w, const Text& s);
    Bytes md5(const Bytes& bytes);
    Bytes sha1(const uint8_t* data, size_t size);
    Bytes aes128(const Bytes& bytes, const Bytes& key);
    Text encryptString(const Text& value, const Text& password);
    void fixDex(Bytes& bytes);
    void validateDex(const Bytes& bytes);
    std::string randomToken();
}
