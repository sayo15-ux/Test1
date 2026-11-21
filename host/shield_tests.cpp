#include "engine.hpp"
#include "payload.hpp"
#include <filesystem>
#include <iostream>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace dexpack;
namespace fs = std::filesystem;

static void rejected(Bytes bytes) {
    bool failed = false;
    try { shield::inspect(bytes.data(), bytes.size()); } catch (const std::exception&) { failed = true; }
    require(failed, "Malformed Shield payload was accepted.");
}
int main(int argc, char** argv) {
    try {
        require(argc == 3, "Expected original APK and empty test directory.");
        fs::path root = fs::absolute(argv[2]);
        require(!fs::exists(root), "Test directory must not already exist."); fs::create_directories(root);
        Input original(argv[1]); auto apk = (root/"protected.apk").string();
        protect(original, apk, 0, {}, {});
        Archive protectedApk(apk); auto bytes = protectedApk.extract("assets/ScKit_shield_v1.dex");
        auto index = shield::inspect(bytes.data(), bytes.size());
        require(index.application == utf8(original.info.applicationName), "Original Application was lost.");
        require(index.hasApplication == original.info.hasApplication && index.dex.size() == original.dexNames.size(), "Shield metadata mismatch.");
        for (const auto& entry : index.dex) require(slice(bytes, entry.offset, entry.size) == original.archive.extract(entry.name), "Packed DEX changed.");
        std::cout << "PASS: original DEX and Application metadata round trip\n";
        auto bad = bytes; bad[index.dex[0].offset+32] ^= 1; rejected(bad);
        fixDex(bad); rejected(bad);
        bad = bytes; put32(bad, 416, 0); fixDex(bad); rejected(bad);
        bad = bytes; put32(bad, 432, NONE); fixDex(bad); rejected(bad);
        bad = bytes; put32(bad, 436, NONE); fixDex(bad); rejected(bad);
        bad = bytes; put16(bad, 424, 65535); fixDex(bad); rejected(bad);
        bad = bytes; bad.resize(bytes.size()-1); fixDex(bad); rejected(bad);
        bad = bytes; bad[440] = '/'; fixDex(bad); rejected(bad);
        for (size_t n : {size_t(0), size_t(32), size_t(415), size_t(425)}) rejected(slice(bytes, 0, n));
        std::cout << "PASS: damaged hashes, offsets, sizes, counts, paths and truncation rejected\n";
        fs::path data = root/"data"; fs::create_directory(data);
        auto installed = shield::install(apk, data.string());
        require(installed.dexPaths.size() == original.dexNames.size(), "Wrong installed DEX count.");
        std::vector<ino_t> inodes;
        for (size_t i = 0; i < installed.dexPaths.size(); ++i) {
            require(readFile(installed.dexPaths[i]) == original.archive.extract(original.dexNames[i]), "Extracted DEX differs.");
            struct stat st{}; require(stat(installed.dexPaths[i].c_str(), &st) == 0 && (st.st_mode & 0777) == 0400, "DEX cache is writable."); inodes.push_back(st.st_ino);
        }
        auto cached = shield::install(apk, data.string());
        require(cached.dexPaths == installed.dexPaths, "Stable payload changed cache key.");
        for (size_t i = 0; i < cached.dexPaths.size(); ++i) { struct stat st{}; stat(cached.dexPaths[i].c_str(), &st); require(st.st_ino == inodes[i], "Valid cache was rewritten."); }
        std::cout << "PASS: read-only cache and repeat-load reuse\n";
        auto target = installed.dexPaths[0]; chmod(target.c_str(), 0600);
        bad = readFile(target); bad.back() ^= 1; writeFile(target, bad); chmod(target.c_str(), 0400);
        shield::install(apk, data.string()); require(readFile(target) == original.archive.extract(original.dexNames[0]), "Modified cache was not repaired.");
        auto outside = root/"outside.dex"; writeFile(outside.string(), ascii("must stay unchanged"));
        fs::remove(target); fs::create_symlink(outside, target);
        shield::install(apk, data.string()); require(!fs::is_symlink(target) && readFile(outside.string()) == ascii("must stay unchanged"), "Cache followed a symlink.");
        std::cout << "PASS: modified cache and symlink replacement\n";
        std::vector<pid_t> children;
        for (int i = 0; i < 4; ++i) {
            pid_t child = fork(); require(child >= 0, "fork failed");
            if (child == 0) { try { shield::install(apk, data.string()); _exit(0); } catch (...) { _exit(1); } }
            children.push_back(child);
        }
        for (pid_t child : children) { int status = 0; require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "Concurrent cache load failed."); }
        std::cout << "PASS: concurrent process cache loads\n";
        for (const auto& entry : fs::recursive_directory_iterator(data)) require(entry.path().filename().string().rfind("payload-", 0) != 0, "Temporary payload was not removed.");
        std::cout << "PASS: temporary-file cleanup\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
