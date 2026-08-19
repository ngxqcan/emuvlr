#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <filesystem>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>

namespace fs = std::filesystem;

// Expected module export signature.
// ctx:      opaque context pointer (currently nullptr)
// args:     task template JSON bytes
// args_len: length of args
// out:      module allocates output buffer (*out = HeapAlloc / malloc)
// out_len:  length of output buffer
// Returns 0 on success, non-zero on error.
typedef int (*VanguardModuleEntryFn)(
    void* ctx,
    const uint8_t* args, size_t args_len,
    uint8_t** out, size_t* out_len);

struct LoadedModule {
    HMODULE handle = nullptr;
    VanguardModuleEntryFn entry = nullptr;
    std::string mod_id;
    fs::path dll_path;        // temp .dll copy used for loading
    fs::path source_path;     // original .bin cache path
};

class ModuleLoader {
public:
    ~ModuleLoader();

    // Load module from cache_path (.bin).
    // Creates a .dll temp copy, loads via LoadLibraryExW, resolves entry point.
    // Returns true on success.
    bool load(const std::string& mod_id, const fs::path& cache_path);

    // Execute a loaded module with args, return output bytes.
    // On crash/error: returns empty vector + logs to stderr.
    std::vector<uint8_t> execute(
        const std::string& mod_id,
        const uint8_t* args, size_t args_len);

    // Unload specific module.
    void unload(const std::string& mod_id);

    // Check if module is already loaded.
    bool is_loaded(const std::string& mod_id) const;

    // Get loaded module pointer (nullptr if not loaded).
    LoadedModule* get_loaded(const std::string& mod_id);

private:
    std::unordered_map<std::string, LoadedModule> loaded_;
};
