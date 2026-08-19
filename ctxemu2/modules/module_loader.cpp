#include "module_loader.hpp"
#include <cstdio>
#include <stdexcept>
#include <windows.h>

#pragma comment(lib, "ole32.lib")

using namespace std;

ModuleLoader::~ModuleLoader() {
    for (auto& [id, mod] : loaded_) {
        if (mod.handle) {
            FreeLibrary(mod.handle);
        }
        if (!mod.dll_path.empty() && fs::exists(mod.dll_path)) {
            try {
                fs::remove(mod.dll_path);
            } catch (...) {}
        }
    }
}

bool ModuleLoader::load(const string& mod_id, const fs::path& cache_path) {
    if (is_loaded(mod_id)) return true;

    if (!fs::exists(cache_path)) {
        fprintf(stderr, "[module_loader] Cache path not found: %s\n", cache_path.string().c_str());
        return false;
    }

    fs::path temp_dll = cache_path;
    temp_dll.replace_extension(".dll");

    try {
        fs::copy_file(cache_path, temp_dll, fs::copy_options::overwrite_existing);
    } catch (const fs::filesystem_error& e) {
        fprintf(stderr, "[module_loader] Failed to copy to dll: %s\n", e.what());
        return false;
    }

    HMODULE handle = LoadLibraryExW(temp_dll.wstring().c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!handle) {
        DWORD err = GetLastError();
        fprintf(stderr, "[module_loader] LoadLibraryExW failed for %s, err: %lu\n", mod_id.c_str(), err);
        try { fs::remove(temp_dll); } catch (...) {}
        return false;
    }

    auto entry = reinterpret_cast<VanguardModuleEntryFn>(GetProcAddress(handle, "vanguard_module_entry"));
    if (!entry) {
        DWORD err = GetLastError();
        fprintf(stderr, "[module_loader] GetProcAddress 'vanguard_module_entry' failed for %s, err: %lu\n", mod_id.c_str(), err);
        FreeLibrary(handle);
        try { fs::remove(temp_dll); } catch (...) {}
        return false;
    }

    LoadedModule mod;
    mod.handle = handle;
    mod.entry = entry;
    mod.mod_id = mod_id;
    mod.dll_path = temp_dll;
    mod.source_path = cache_path;

    loaded_[mod_id] = mod;
    return true;
}

int ExecuteModuleSEH(VanguardModuleEntryFn entry, const uint8_t* args, size_t args_len, uint8_t** out_ptr, size_t* out_len) {
    int ret = -1;
    __try {
        ret = entry(nullptr, args, args_len, out_ptr, out_len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ret = -2;
    }
    return ret;
}

vector<uint8_t> ModuleLoader::execute(const string& mod_id, const uint8_t* args, size_t args_len) {
    auto mod = get_loaded(mod_id);
    if (!mod) {
        fprintf(stderr, "[module_loader] Cannot execute, module not loaded: %s\n", mod_id.c_str());
        return {};
    }

    uint8_t* out_ptr = nullptr;
    size_t out_len = 0;
    
    int ret = ExecuteModuleSEH(mod->entry, args, args_len, &out_ptr, &out_len);
    
    if (ret == -2) {
        fprintf(stderr, "[module_loader] SEH Exception during module execution: %s\n", mod_id.c_str());
        return {};
    }

    if (ret != 0) {
        fprintf(stderr, "[module_loader] Module %s returned error code: %d\n", mod_id.c_str(), ret);
        // Clean up out_ptr just in case it allocated something before failing
        if (out_ptr) {
            // Assuming CoTaskMemFree as standard COM allocator fallback, or free() if they use CRT
            // For safety, we shouldn't attempt to free if ret != 0 unless specifically documented.
            // Let's assume on failure out_ptr should be ignored/freed.
            CoTaskMemFree(out_ptr); 
        }
        return {};
    }

    vector<uint8_t> result;
    if (out_ptr && out_len > 0) {
        result.assign(out_ptr, out_ptr + out_len);
        // Modules usually allocate with CoTaskMemAlloc for interop, 
        // or we need a specific export to free it. 
        // Assuming CoTaskMemFree for standard Windows interop.
        CoTaskMemFree(out_ptr);
    }

    return result;
}

void ModuleLoader::unload(const string& mod_id) {
    auto it = loaded_.find(mod_id);
    if (it != loaded_.end()) {
        if (it->second.handle) {
            FreeLibrary(it->second.handle);
        }
        if (!it->second.dll_path.empty() && fs::exists(it->second.dll_path)) {
            try { fs::remove(it->second.dll_path); } catch (...) {}
        }
        loaded_.erase(it);
    }
}

bool ModuleLoader::is_loaded(const string& mod_id) const {
    return loaded_.count(mod_id) > 0;
}

LoadedModule* ModuleLoader::get_loaded(const string& mod_id) {
    auto it = loaded_.find(mod_id);
    if (it != loaded_.end()) {
        return &it->second;
    }
    return nullptr;
}
