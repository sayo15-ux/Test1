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
#include <set>
#include <elf.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#define LOG_TAG "sigfall"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

const char* const kHidden[] = {
    "libsigfall", "fancy/lib", "fancy/dex", "fancy_origin"
};

bool hiddenPath(const char* path) {
    if (!path) return false;
    for (const char* needle : kHidden) if (strstr(path, needle)) return true;
    return false;
}

bool isMaps(const char* path) {
    return path && strcmp(path, "/proc/self/maps") == 0;
}

int rawOpen(const char* path, int flags);

std::string processName() {
    int fd = rawOpen("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    char buffer[512] = {0};
    long size = syscall(__NR_read, fd, buffer, sizeof(buffer) - 1);
    syscall(__NR_close, fd);
    if (size <= 0) return {};
    return std::string(buffer, (size_t)strnlen(buffer, sizeof(buffer) - 1));
}

std::string originApkPath() {
    static std::string cached;
    if (!cached.empty()) return cached;
    std::string name = processName();
    if (name.empty() || name.find('/') != std::string::npos) return {};
    for (const char* prefix : {"/data/user/0/", "/data/data/"}) {
        std::string candidate = std::string(prefix) + name + "/files/fancy/origin.apk";
        int fd = rawOpen(candidate.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            syscall(__NR_close, fd);
            cached = candidate;
            return cached;
        }
    }
    return {};
}

const char* resolvePath(const char* path) {
    if (path && strstr(path, "/data/app/") && strstr(path, ".apk")) {
        std::string origin = originApkPath();
        if (!origin.empty()) {
            static std::string redirected;
            redirected = origin;
            return redirected.c_str();
        }
    }
    return path;
}

const char* hookPath(const char* path) {
    const char* resolved = resolvePath(path);
    if (resolved != path) return resolved;
    return hiddenPath(path) ? nullptr : path;
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

int hookedOpen(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (isMaps(path)) return filteredMapsFd();
    const char* target = hookPath(path);
    if (!target) { errno = ENOENT; return -1; }
    return g_open ? g_open(target, flags, mode) : -1;
}

int hookedOpenat(int dirfd, const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    if (isMaps(path)) return filteredMapsFd();
    const char* target = hookPath(path);
    if (!target) { errno = ENOENT; return -1; }
    return g_openat ? g_openat(dirfd, target, flags, mode) : -1;
}

FILE* hookedFopen(const char* path, const char* mode) {
    if (isMaps(path)) {
        int fd = filteredMapsFd();
        return fd < 0 ? nullptr : fdopen(fd, mode);
    }
    const char* target = hookPath(path);
    if (!target) { errno = ENOENT; return nullptr; }
    return g_fopen ? g_fopen(target, mode) : nullptr;
}

int hookedAccess(const char* path, int mode) {
    if (isMaps(path)) return 0;
    const char* target = hookPath(path);
    if (!target) { errno = ENOENT; return -1; }
    return g_access ? g_access(target, mode) : -1;
}

int hookedStat(const char* path, struct stat* info) {
    if (isMaps(path)) return 0;
    const char* target = hookPath(path);
    if (!target) { errno = ENOENT; return -1; }
    return g_stat ? g_stat(target, info) : -1;
}

int hookedFstatat(int dirfd, const char* path, struct stat* info, int flags) {
    if (isMaps(path)) return 0;
    const char* target = hookPath(path);
    if (!target) { errno = ENOENT; return -1; }
    return g_fstatat ? g_fstatat(dirfd, target, info, flags) : -1;
}

struct HookRecord {
    const char* name;
    void* replacement;
};

static const HookRecord kHooks[] = {
    {"open", (void*)hookedOpen},
    {"openat", (void*)hookedOpenat},
    {"fopen", (void*)hookedFopen},
    {"access", (void*)hookedAccess},
    {"stat", (void*)hookedStat},
    {"fstatat", (void*)hookedFstatat},
};

void writeSlot(uintptr_t slot, void* value) {
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;
    uintptr_t page = slot & ~((uintptr_t)pageSize - 1);
    if (mprotect((void*)page, (size_t)pageSize, PROT_READ | PROT_WRITE) != 0) {
        if (mprotect((void*)page, (size_t)pageSize * 2, PROT_READ | PROT_WRITE) != 0) return;
    }
    *(void**)slot = value;
}

void patchSlotForName(const char* name, uintptr_t slot) {
    for (const auto& hook : kHooks) {
        if (strcmp(name, hook.name) == 0) {
            writeSlot(slot, hook.replacement);
            return;
        }
    }
}

void patchLibrary64(uintptr_t start) {
    Elf64_Ehdr* header = (Elf64_Ehdr*)start;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) return;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(start + header->e_phoff);
    uintptr_t bias = start;
    uintptr_t dynamic = 0;
    for (int i = 0; i < header->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
            bias = start - phdr[i].p_vaddr;
            break;
        }
    }
    for (int i = 0; i < header->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = bias + phdr[i].p_vaddr;
            break;
        }
    }
    if (!dynamic) return;
    uintptr_t strtab = 0, symtab = 0, jmprel = 0;
    size_t pltrelsz = 0, syment = sizeof(Elf64_Sym);
    for (Elf64_Dyn* dyn = (Elf64_Dyn*)dynamic; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
            case DT_STRTAB: strtab = bias + dyn->d_un.d_ptr; break;
            case DT_SYMTAB: symtab = bias + dyn->d_un.d_ptr; break;
            case DT_JMPREL: jmprel = bias + dyn->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = (size_t)dyn->d_un.d_val; break;
            case DT_SYMENT: syment = (size_t)dyn->d_un.d_val; break;
            default: break;
        }
    }
    if (!strtab || !symtab || !jmprel || !pltrelsz) return;
    Elf64_Rela* rela = (Elf64_Rela*)jmprel;
    for (size_t i = 0; i < pltrelsz / sizeof(Elf64_Rela); ++i) {
        uint32_t type = (uint32_t)ELF64_R_TYPE(rela[i].r_info);
        if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT) continue;
        uint32_t index = (uint32_t)ELF64_R_SYM(rela[i].r_info);
        Elf64_Sym* symbol = (Elf64_Sym*)(symtab + index * syment);
        const char* name = (const char*)(strtab + symbol->st_name);
        patchSlotForName(name, bias + rela[i].r_offset);
    }
}

void patchLibrary32(uintptr_t start) {
    Elf32_Ehdr* header = (Elf32_Ehdr*)start;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) return;
    Elf32_Phdr* phdr = (Elf32_Phdr*)(start + header->e_phoff);
    uintptr_t bias = start;
    uintptr_t dynamic = 0;
    for (int i = 0; i < header->e_phnum; ++i) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) {
            bias = start - phdr[i].p_vaddr;
            break;
        }
    }
    for (int i = 0; i < header->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dynamic = bias + phdr[i].p_vaddr;
            break;
        }
    }
    if (!dynamic) return;
    uintptr_t strtab = 0, symtab = 0, jmprel = 0;
    size_t pltrelsz = 0, syment = sizeof(Elf32_Sym);
    for (Elf32_Dyn* dyn = (Elf32_Dyn*)dynamic; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
            case DT_STRTAB: strtab = bias + dyn->d_un.d_ptr; break;
            case DT_SYMTAB: symtab = bias + dyn->d_un.d_ptr; break;
            case DT_JMPREL: jmprel = bias + dyn->d_un.d_ptr; break;
            case DT_PLTRELSZ: pltrelsz = (size_t)dyn->d_un.d_val; break;
            case DT_SYMENT: syment = (size_t)dyn->d_un.d_val; break;
            default: break;
        }
    }
    if (!strtab || !symtab || !jmprel || !pltrelsz) return;
    Elf32_Rel* rel = (Elf32_Rel*)jmprel;
    for (size_t i = 0; i < pltrelsz / sizeof(Elf32_Rel); ++i) {
        uint32_t type = ELF32_R_TYPE(rel[i].r_info);
        if (type != R_ARM_JUMP_SLOT && type != R_ARM_GLOB_DAT) continue;
        uint32_t index = ELF32_R_SYM(rel[i].r_info);
        Elf32_Sym* symbol = (Elf32_Sym*)(symtab + index * syment);
        const char* name = (const char*)(strtab + symbol->st_name);
        patchSlotForName(name, bias + rel[i].r_offset);
    }
}

bool skipLibrary(const char* path) {
    return strstr(path, "libc.so") || strstr(path, "linker") ||
           strstr(path, "libsigfall") || !strstr(path, ".so");
}

void patchLibraries() {
    int fd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    std::string content;
    char buffer[8192];
    for (;;) {
        long n = syscall(__NR_read, fd, buffer, sizeof(buffer));
        if (n < 0) { syscall(__NR_close, fd); return; }
        if (n == 0) break;
        content.append(buffer, (size_t)n);
    }
    syscall(__NR_close, fd);
    std::set<std::string> seen;
    size_t start = 0;
    while (start < content.size()) {
        size_t end = content.find('\n', start);
        if (end == std::string::npos) end = content.size();
        std::string line = content.substr(start, end - start);
        unsigned long begin = 0, offset = 0;
        char perms[16] = {0}, dev[64] = {0};
        unsigned long inode = 0;
        int consumed = 0;
        if (sscanf(line.c_str(), "%lx-%lx %15s %lx %63s %lu %n",
                   &begin, &end, perms, &offset, dev, &inode, &consumed) >= 6 && consumed > 0) {
            std::string path = line.substr((size_t)consumed);
            size_t first = path.find_first_not_of(" \t");
            if (first != std::string::npos) path = path.substr(first);
            if (!path.empty() && offset == 0 && !skipLibrary(path.c_str()) && seen.insert(path).second) {
                uintptr_t base = (uintptr_t)begin;
                Elf64_Ehdr* header = (Elf64_Ehdr*)base;
                if (memcmp(header->e_ident, ELFMAG, SELFMAG) == 0) {
                    if (header->e_ident[EI_CLASS] == ELFCLASS64) patchLibrary64(base);
                    else if (header->e_ident[EI_CLASS] == ELFCLASS32) patchLibrary32(base);
                }
            }
        }
        start = end + 1;
    }
}

void* patchThread(void*) {
    for (;;) {
        patchLibraries();
        usleep(50000);
    }
    return nullptr;
}

void installHooks() {
    g_open = (OpenFn)dlsym(RTLD_DEFAULT, "open");
    g_openat = (OpenatFn)dlsym(RTLD_DEFAULT, "openat");
    g_fopen = (FopenFn)dlsym(RTLD_DEFAULT, "fopen");
    g_access = (AccessFn)dlsym(RTLD_DEFAULT, "access");
    g_stat = (StatFn)dlsym(RTLD_DEFAULT, "stat");
    g_fstatat = (FstatatFn)dlsym(RTLD_DEFAULT, "fstatat");
    pthread_t thread;
    if (pthread_create(&thread, nullptr, patchThread, nullptr) == 0) {
        pthread_detach(thread);
    }
    LOGI("native bypass hooks installed via GOT patching");
}
}  // namespace

void exemptHiddenApis(JNIEnv* env) {
    jclass runtimeClass = env->FindClass("dalvik/system/VMRuntime");
    if (!runtimeClass || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jmethodID getRuntime = env->GetStaticMethodID(runtimeClass, "getRuntime", "()Ldalvik/system/VMRuntime;");
    if (!getRuntime || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jobject runtime = env->CallStaticObjectMethod(runtimeClass, getRuntime);
    if (!runtime || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jmethodID setExemptions = env->GetMethodID(runtimeClass, "setHiddenApiExemptions", "([Ljava/lang/String;)V");
    if (!setExemptions || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jstring signature = env->NewStringUTF("L");
    jobjectArray exemptions = env->NewObjectArray(1, env->FindClass("java/lang/String"), signature);
    env->CallVoidMethod(runtime, setExemptions, exemptions);
    env->ExceptionClear();
    LOGI("hidden API exemptions installed");
}

extern "C" jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    exemptHiddenApis(env);
    installHooks();
    return JNI_VERSION_1_6;
}
