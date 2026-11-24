#include "payload.hpp"
#include "archive.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

namespace dexpack::shield {
    namespace {
        constexpr size_t PREFIX = 416;
        struct Cursor {
            const uint8_t* bytes;
            size_t size, offset = 0;
            void need(size_t n) const { require(offset <= size && n <= size - offset, "Truncated Shield payload."); }
            uint16_t u16() { need(2); uint16_t v = uint16_t(bytes[offset]) | uint16_t(bytes[offset+1]) << 8; offset += 2; return v; }
            uint32_t u32() { uint32_t a = u16(); return a | uint32_t(u16()) << 16; }
            std::string text(size_t n) { need(n); std::string s(reinterpret_cast<const char*>(bytes+offset), n); offset += n; return s; }
        };
        uint32_t word(const uint8_t* p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24; }
        std::string decode(const std::string& value) {
            require(value.size() % 2 == 0, "Invalid Shield metadata encoding.");
            auto digit = [](char c) -> unsigned { if (c >= '0' && c <= '9') return unsigned(c-'0'); if (c >= 'a' && c <= 'f') return unsigned(c-'a'+10); if (c >= 'A' && c <= 'F') return unsigned(c-'A'+10); throw std::runtime_error("Invalid Shield metadata hex."); };
            std::string out;
            for (size_t i = 0; i < value.size(); i += 2) out.push_back(char(((digit(value[i]) << 4) | digit(value[i+1])) ^ 56));
            require(out.find('\0') == std::string::npos && validText(utf16(out)), "Invalid Shield metadata text."); return out;
        }
        void dex(const uint8_t* p, size_t size) {
            require(size >= 112 && !std::memcmp(p, "dex\n", 4) && p[7] == 0, "Invalid packed DEX header.");
            std::string version(reinterpret_cast<const char*>(p+4), 3);
            require(version == "035" || version == "036" || version == "037" || version == "038" || version == "039" || version == "040", "Unsupported packed DEX version.");
            require(word(p+32) == size && word(p+36) == 112 && word(p+40) == 0x12345678, "Packed DEX size or endian mismatch.");
            auto hash = sha1(p+32, size-32); require(!std::memcmp(hash.data(), p+12, 20), "Packed DEX SHA-1 mismatch.");
            uLong checksum = adler32(0, Z_NULL, 0);
            for (size_t off = 12; off < size;) { size_t n = std::min<size_t>(65536, size-off); checksum = adler32(checksum, p+off, uInt(n)); off += n; }
            require(uint32_t(checksum) == word(p+8), "Packed DEX checksum mismatch.");
        }
        struct Fd {
            int value;
            explicit Fd(int v) : value(v) { require(v >= 0, "Cannot open private Shield cache: " + std::string(std::strerror(errno))); }
            ~Fd() { if (value >= 0) close(value); }
            Fd(const Fd&) = delete;
        };
        struct Mapping {
            const uint8_t* data;
            size_t size;
            Mapping(int fd, size_t n) : size(n) {
                require(n > 0, "Empty Shield cache file.");
                void* mapped = mmap(nullptr, n, PROT_READ, MAP_PRIVATE, fd, 0);
                require(mapped != MAP_FAILED, "Cannot map Shield payload."); data = static_cast<const uint8_t*>(mapped);
            }
            ~Mapping() { munmap(const_cast<uint8_t*>(data), size); }
        };
        void directory(const std::string& name) {
            require(mkdir(name.c_str(), 0700) == 0 || errno == EEXIST, "Cannot create Shield cache directory.");
            struct stat st{}; require(lstat(name.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == getuid(), "Unsafe Shield cache directory.");
        }
        void writeAll(int fd, const uint8_t* p, size_t n) {
            while (n) { ssize_t done = write(fd, p, std::min<size_t>(n, 65536)); if (done < 0 && errno == EINTR) continue; require(done > 0, "Cannot write Shield cache; check available storage."); p += done; n -= size_t(done); }
        }
        struct Temporary {
            std::string name;
            int fd;
            explicit Temporary(const std::string& pattern) {
                std::vector<char> path(pattern.begin(), pattern.end()); path.push_back(0); fd = mkstemp(path.data());
                require(fd >= 0, "Cannot create Shield cache file."); name = path.data();
                if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || fchmod(fd, 0400) != 0) { close(fd); unlink(name.c_str()); throw std::runtime_error("Cannot make Shield cache read-only."); }
            }
            ~Temporary() { close(fd); if (!name.empty()) unlink(name.c_str()); }
            Temporary(const Temporary&) = delete;
            void commit(const std::string& destination) {
                require(fsync(fd) == 0, "Cannot sync Shield cache file.");
                require(rename(name.c_str(), destination.c_str()) == 0, "Cannot publish Shield cache file."); name.clear();
            }
        };
        bool matches(const std::string& path, const uint8_t* bytes, size_t size) {
            int raw = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (raw < 0) return false; Fd fd(raw);
            struct stat st{}; if (fstat(fd.value, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || uint64_t(st.st_size) != size || (st.st_mode & 0222) || st.st_uid != getuid()) return false;
            std::array<uint8_t,65536> buffer{};
            for (size_t off = 0; off < size;) {
                size_t n = std::min(buffer.size(), size-off); size_t count = 0;
                while (count < n) { size_t want = std::min<size_t>(n-count, buffer.size()); ssize_t got = read(fd.value, buffer.data()+count, want); if (got < 0 && errno == EINTR) continue; if (got <= 0) return false; count += size_t(got); }
                if (std::memcmp(bytes+off, buffer.data(), n)) return false;
                off += n;
            }
            return true;
        }
    }
    Index inspect(const uint8_t* bytes, size_t size) {
        require(bytes != nullptr && size >= PREFIX+10 && size < 0xffffffffu, "Invalid Shield container size."); dex(bytes, size);
        Cursor reader{bytes+PREFIX, size-PREFIX};
        require(reader.u32() == 0xef0051 && reader.u32() == size-PREFIX, "Invalid Shield container header.");
        uint16_t count = reader.u16(); require(count >= 4, "Shield container has no DEX files.");
        std::vector<Entry> entries; std::set<std::string> names;
        for (unsigned i = 0; i < count; ++i) {
            require(reader.u32() == 0xef0061, "Invalid Shield index entry.");
            uint16_t length = reader.u16(); uint32_t offset = reader.u32(), lengthData = reader.u32(); std::string name = reader.text(length);
            require(!name.empty() && name.find('\0') == std::string::npos && names.insert(name).second, "Invalid or duplicate Shield entry.");
            require(offset <= reader.size && lengthData <= reader.size-offset, "Shield entry is outside its container."); entries.push_back({name, offset, lengthData});
        }
        size_t end = reader.offset; std::map<std::string,std::string> metadata; Index index;
        for (const auto& entry : entries) {
            require(entry.offset == end, "Overlapping or non-contiguous Shield entries."); end += entry.size;
            const uint8_t* p = reader.bytes + entry.offset;
            if (dexEntry(entry.name)) { index.dex.push_back({entry.name, uint32_t(PREFIX+entry.offset), entry.size}); dex(p, entry.size); }
            else { auto key = decode(entry.name); require(metadata.emplace(key, decode(std::string(reinterpret_cast<const char*>(p), entry.size))).second, "Duplicate Shield metadata."); }
        }
        require(end == reader.size && !index.dex.empty(), "Invalid Shield container length.");
        std::string joined;
        for (size_t i = 0; i < index.dex.size(); ++i) {
            std::string expected = i ? "classes"+std::to_string(i+1)+".dex" : "classes.dex";
            require(index.dex[i].name == expected, "Non-contiguous Shield DEX names."); if (i) joined += ','; joined += expected;
        }
        require(metadata.size() == 3 && metadata.count("dexNames") && metadata.count("originApplicationName") && metadata.count("existApplicationClass"), "Shield metadata is incomplete.");
        require(metadata.at("dexNames") == joined, "Shield DEX metadata does not match its index.");
        index.application = metadata.at("originApplicationName"); auto exists = metadata.at("existApplicationClass");
        require(exists == "0" || exists == "1", "Invalid Shield application flag."); index.hasApplication = exists == "1";
        require(!index.application.empty(), "Original Application name is missing."); return index;
    }
    Installed install(const std::string& apk, const std::string& dataDirectory) {
        require(!apk.empty() && !dataDirectory.empty(), "Missing Shield APK or data directory.");
        std::string base = dataDirectory+"/code_cache"; directory(base); base += "/dexpack_shield"; directory(base);
        Fd lock(open((base+"/cache.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
        struct stat lockStat{};
        require(fstat(lock.value, &lockStat) == 0 && S_ISREG(lockStat.st_mode) && lockStat.st_uid == getuid(), "Unsafe Shield cache lock.");
        require(flock(lock.value, LOCK_EX) == 0, "Cannot lock Shield cache.");
        Archive archive(apk); auto entry = archive.find("assets/Fallen_shield_v1.dex"); require(entry != nullptr, "Shield payload is missing.");
        Temporary payload(base+"/payload-XXXXXX");
        archive.extractTo(*entry, [&](const uint8_t* p, size_t n) { writeAll(payload.fd, p, n); });
        Mapping mapping(payload.fd, entry->size); auto index = inspect(mapping.data, mapping.size);
        std::string version = base+"/"+hex(Bytes(mapping.data+12, mapping.data+32)); directory(version);
        Installed result; result.application = index.application; result.optimizedDirectory = version+"/opt"; directory(result.optimizedDirectory);
        for (const auto& item : index.dex) {
            std::string path = version+"/"+item.name; const uint8_t* data = mapping.data+item.offset;
            if (!matches(path, data, item.size)) { Temporary next(version+"/dex-XXXXXX"); writeAll(next.fd, data, item.size); next.commit(path); }
            result.dexPaths.push_back(path);
        }
        return result;
    }
}
