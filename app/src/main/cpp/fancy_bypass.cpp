#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#define LOG_TAG "fancy-bypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

pthread_once_t g_once = PTHREAD_ONCE_INIT;

const char* const kHidden[] = {
    "origin.apk", "libfancy-bypass", "fancy/lib", "fancy/dex", "fancy_origin"
};

bool hiddenPath(const char* path) {
    if (!path) return false;
    for (const char* needle : kHidden) if (strstr(path, needle)) return true;
    return false;
}

bool isMaps(const char* path) {
    return path && strcmp(path, "/proc/self/maps") == 0;
}

int rawOpen(const char* path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags, 0);
}

int filteredMapsFd() {
    int fd = rawOpen("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    std::string content;
    char buffer[4096];
    for (;;) {
        long n = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (n < 0) { syscall(__NR_close, fd); return -1; }
        if (n == 0) break;
        content.append(buffer, (size_t)n);
    }
    syscall(__NR_close, fd);
    std::string filtered;
    filtered.reserve(content.size());
    size_t start = 0;
    while (start < content.size()) {
        size_t end = content.find('\n', start);
        if (end == std::string::npos) end = content.size();
        std::string line = content.substr(start, end - start);
        bool drop = false;
        for (const char* needle : kHidden) if (line.find(needle) != std::string::npos) { drop = true; break; }
        if (!drop) { filtered += line; filtered += '\n'; }
        start = end + 1;
    }
    int memfd = (int)syscall(__NR_memfd_create, "fancy_maps", MFD_CLOEXEC);
    if (memfd < 0) return -1;
    size_t off = 0;
    while (off < filtered.size()) {
        long n = syscall(__NR_write, memfd, filtered.data() + off, filtered.size() - off);
        if (n <= 0) { syscall(__NR_close, memfd); return -1; }
        off += (size_t)n;
    }
    syscall(__NR_lseek, memfd, 0, SEEK_SET);
    return memfd;
}

using OpenFn = int (*)(const char*, int, ...);
using OpenatFn = int (*)(int, const char*, int, ...);
using FopenFn = FILE* (*)(const char*, const char*);
using AccessFn = int (*)(const char*, int);
using StatFn = int (*)(const char*, struct stat*);
using FstatatFn = int (*)(int, const char*, struct stat*, int);

OpenFn g_open = nullptr;
OpenatFn g_openat = nullptr;
FopenFn g_fopen = nullptr;
AccessFn g_access = nullptr;
StatFn g_stat = nullptr;
FstatatFn g_fstatat = nullptr;

void* g_openStub = nullptr;
void* g_openatStub = nullptr;
void* g_fopenStub = nullptr;
void* g_accessStub = nullptr;
void* g_statStub = nullptr;
void* g_fstatatStub = nullptr;

void* allocExec(size_t size) {
    void* memory = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return memory == MAP_FAILED ? nullptr : memory;
}

void patchFunction(void* target, void* stub, void* replacement, size_t originalBytes) {
    if (!target || !stub || !replacement) return;
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;
    uintptr_t page = (uintptr_t)target & ~(uintptr_t)(pageSize - 1);
    if (mprotect((void*)page, (size_t)pageSize * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("mprotect failed");
        return;
    }
    memcpy(stub, target, originalBytes);
#if defined(__aarch64__)
    uint8_t* code = (uint8_t*)stub + originalBytes;
    code[0] = 0x50; code[1] = 0x00; code[2] = 0x00; code[3] = 0x58;
    code[4] = 0x00; code[5] = 0x00; code[6] = 0x1f; code[7] = 0xd6;
    uint64_t next = (uint64_t)((uint8_t*)target + originalBytes);
    memcpy(code + 8, &next, sizeof(next));
    __builtin___clear_cache((char*)stub, (char*)stub + originalBytes + 16);
    uint8_t patch[16];
    patch[0] = 0x50; patch[1] = 0x00; patch[2] = 0x00; patch[3] = 0x58;
    patch[4] = 0x00; patch[5] = 0x00; patch[6] = 0x1f; patch[7] = 0xd6;
    uint64_t hook = (uint64_t)replacement;
    memcpy(patch + 8, &hook, sizeof(hook));
    memcpy(target, patch, sizeof(patch));
#else
    uint8_t* code = (uint8_t*)stub + originalBytes;
    code[0] = 0x04; code[1] = 0xf0; code[2] = 0x1f; code[3] = 0xe5;
    uint32_t next = (uint32_t)((uint8_t*)target + originalBytes);
    memcpy(code + 4, &next, sizeof(next));
    __builtin___clear_cache((char*)stub, (char*)stub + originalBytes + 8);
    uint8_t patch[8];
    patch[0] = 0x04; patch[1] = 0xf0; patch[2] = 0x1f; patch[3] = 0xe5;
    uint32_t hook = (uint32_t)replacement;
    memcpy(patch + 4, &hook, sizeof(hook));
    memcpy(target, patch, sizeof(patch));
#endif
    __builtin___clear_cache((char*)target, (char*)target + originalBytes);
    mprotect((void*)page, (size_t)pageSize * 2, PROT_READ | PROT_EXEC);
}

template <typename Fn>
void hook(Fn& original, void* replacement, void*& stub, size_t bytes, const char* name) {
    void* target = dlsym(RTLD_DEFAULT, name);
    if (!target) { LOGE("dlsym %s failed", name); return; }
    stub = allocExec(bytes + 32);
    if (!stub) { LOGE("allocExec failed for %s", name); return; }
    patchFunction(target, stub, replacement, bytes);
    original = reinterpret_cast<Fn>(stub);
}

int hookedOpen(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (isMaps(path)) return filteredMapsFd();
    if (hiddenPath(path)) { errno = ENOENT; return -1; }
    return g_open ? g_open(path, flags, mode) : -1;
}

int hookedOpenat(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (isMaps(path)) return filteredMapsFd();
    if (hiddenPath(path)) { errno = ENOENT; return -1; }
    return g_openat ? g_openat(dirfd, path, flags, mode) : -1;
}

FILE* hookedFopen(const char* path, const char* mode) {
    if (isMaps(path)) {
        int fd = filteredMapsFd();
        return fd < 0 ? nullptr : fdopen(fd, mode);
    }
    if (hiddenPath(path)) { errno = ENOENT; return nullptr; }
    return g_fopen ? g_fopen(path, mode) : nullptr;
}

int hookedAccess(const char* path, int mode) {
    if (isMaps(path)) return 0;
    if (hiddenPath(path)) { errno = ENOENT; return -1; }
    return g_access ? g_access(path, mode) : -1;
}

int hookedStat(const char* path, struct stat* info) {
    if (isMaps(path)) return 0;
    if (hiddenPath(path)) { errno = ENOENT; return -1; }
    return g_stat ? g_stat(path, info) : -1;
}

int hookedFstatat(int dirfd, const char* path, struct stat* info, int flags) {
    if (isMaps(path)) return 0;
    if (hiddenPath(path)) { errno = ENOENT; return -1; }
    return g_fstatat ? g_fstatat(dirfd, path, info, flags) : -1;
}

void installHooks() {
#if defined(__aarch64__)
    constexpr size_t kBytes = 16;
#else
    constexpr size_t kBytes = 8;
#endif
    hook(g_open, (void*)hookedOpen, g_openStub, kBytes, "open");
    hook(g_openat, (void*)hookedOpenat, g_openatStub, kBytes, "openat");
    hook(g_fopen, (void*)hookedFopen, g_fopenStub, kBytes, "fopen");
    hook(g_access, (void*)hookedAccess, g_accessStub, kBytes, "access");
    hook(g_stat, (void*)hookedStat, g_statStub, kBytes, "stat");
    hook(g_fstatat, (void*)hookedFstatat, g_fstatatStub, kBytes, "fstatat");
    LOGI("native bypass hooks installed");
}

}  // namespace

extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    // Inline hooks disabled: raw byte patching breaks PC-relative instructions and caused SIGSEGV.
    return JNI_VERSION_1_6;
}
