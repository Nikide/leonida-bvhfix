// gta6rt: native runtime for the Xbox Series build.
//
//   gta6rt --dry-run <image> [--game-dir DIR] [--overlay DIR]
//       Maps the image and its bundled modules, applies relocations, binds every import, installs static TLS for
//       this thread and prints a report. No code from the mapped images
//       runs. TLS needs the runtime's own gta6rt_tls_host.dll, which reserves the module TLS index; system DLLs are
//       loaded to resolve host imports, as before.
//
//   gta6rt --init <image> [--game-dir DIR] [--overlay DIR]
//       The same mapping, then each loaded DLL's TLS callbacks and DllMain(DLL_PROCESS_ATTACH) are run.
//
//   gta6rt --run <exe> [--game-dir DIR] [--overlay DIR] [--trace-d3d12] [--trace FILE] [-- game arguments...]
//       The same, then the EXE's own TLS callbacks and its entry point, on a game thread. The game's argv and
//       command line are <exe name> plus the arguments after "--"; exit/ExitProcess from the game end the run
//       (shims/process.cpp). gta6rt prints the binding report first and returns the game's exit code.
//
// --game-dir is also where a title's GAME: paths read from; anything it writes or deletes goes to the overlay
// (--overlay, default <game-dir>/overlay) so the package is never modified (shims/file_system.cpp).
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <malloc.h>
#include <map>
#include <string>
#include <system_error>
#include <vector>

#include "base_reservation.h"
#include "code_hooks.h"
#include "cpu_emulation.h"
#include "mods.h"
#include "pe_loader.h"

namespace rt::shims { std::size_t xbox_bvh_builder_live_count(); }
static volatile std::size_t g_xbox_bvh_builder_link = rt::shims::xbox_bvh_builder_live_count();
#include "../shims/d3d12_trace.h"
#include "../shims/file_system.h"
#include "../shims/process_shim.h"
#include "../shims/shims.h"
#include "../shims/startup_trace.h"

namespace {

const char* binding_name(rt::Binding b) {
    switch (b) {
        case rt::Binding::Shim: return "shim";
        case rt::Binding::Host: return "host";
        case rt::Binding::Module: return "module";
        default: return "UNIMPLEMENTED";
    }
}

int usage() {
    std::fprintf(stderr,
                 "usage: gta6rt --dry-run <image> [--game-dir DIR] [--overlay DIR] [--mods DIR] [--archetype-lookup RVA[,ARG]] [--view-mode-getter RVA] [--trace FILE]\n"
                 "       gta6rt --init <image> [--game-dir DIR] [--overlay DIR] [--mods DIR] [--archetype-lookup RVA[,ARG]] [--view-mode-getter RVA] [--trace-d3d12] [--trace FILE]\n"
                 "       gta6rt --run <exe> [--game-dir DIR] [--overlay DIR] [--mods DIR] [--archetype-lookup RVA[,ARG]] [--view-mode-getter RVA] [--trace-d3d12] [--trace FILE] [-- game arguments...]\n");
    return 2;
}

}  // namespace

namespace {

LONG CALLBACK crash_logger(EXCEPTION_POINTERS* info) {
    if (!info || !info->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const EXCEPTION_RECORD& r = *info->ExceptionRecord;
    if (r.ExceptionCode != 0xC0000005 && r.ExceptionCode != 0xC0000374 && r.ExceptionCode != 0x80000003 &&
        r.ExceptionCode != 0xC0000409 && r.ExceptionCode != 0xC00000FD)
        return EXCEPTION_CONTINUE_SEARCH;
    const void* access = r.NumberParameters >= 2 ? reinterpret_cast<void*>(r.ExceptionInformation[1]) : nullptr;
    char module[MAX_PATH] = {};
    HMODULE host = nullptr;
    const auto address = reinterpret_cast<LPCSTR>(r.ExceptionAddress);
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           address, &host) &&
        host)
        GetModuleFileNameA(host, module, MAX_PATH);
    std::fprintf(stderr, "[rt] crash-veh: code=0x%08lx addr=%p module=%s+0x%llx access=%p tid=%lu\n", r.ExceptionCode,
                 r.ExceptionAddress, module[0] ? module : "?", host ? static_cast<unsigned long long>(
                     reinterpret_cast<uintptr_t>(r.ExceptionAddress) - reinterpret_cast<uintptr_t>(host)) : 0ull,
                 access, GetCurrentThreadId());
    if (info->ContextRecord) {
        const CONTEXT& c = *info->ContextRecord;
        std::fprintf(stderr,
                     "[rt] crash-context: rip=%p rsp=%p rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p rbp=%p "
                     "r8=%p r9=%p r10=%p r11=%p r12=%p r13=%p r14=%p r15=%p\n",
                     reinterpret_cast<void*>(c.Rip), reinterpret_cast<void*>(c.Rsp),
                     reinterpret_cast<void*>(c.Rax), reinterpret_cast<void*>(c.Rbx),
                     reinterpret_cast<void*>(c.Rcx), reinterpret_cast<void*>(c.Rdx),
                     reinterpret_cast<void*>(c.Rsi), reinterpret_cast<void*>(c.Rdi),
                     reinterpret_cast<void*>(c.Rbp), reinterpret_cast<void*>(c.R8),
                     reinterpret_cast<void*>(c.R9), reinterpret_cast<void*>(c.R10),
                     reinterpret_cast<void*>(c.R11), reinterpret_cast<void*>(c.R12),
                     reinterpret_cast<void*>(c.R13), reinterpret_cast<void*>(c.R14),
                     reinterpret_cast<void*>(c.R15));
        if (c.Rip == 0) {
            __try {
                const auto object = static_cast<std::uint64_t>(c.Rax);
                const auto vtable = *reinterpret_cast<const std::uint64_t*>(object);
                const auto slot146 = *reinterpret_cast<const std::uint64_t*>(vtable + 0x490);
                char where[MAX_PATH] = {};
                HMODULE holder = nullptr;
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   reinterpret_cast<LPCSTR>(vtable), &holder);
                if (holder) GetModuleFileNameA(holder, where, MAX_PATH);
                std::fprintf(stderr, "[rt] nullcall: rax=%p vtable=%p slot146=%p module=%s\n",
                             reinterpret_cast<void*>(object), reinterpret_cast<void*>(vtable),
                             reinterpret_cast<void*>(slot146), where[0] ? where : "?");
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                std::fprintf(stderr, "[rt] nullcall: unreadable\n");
            }
        }
        __try {
            const auto* stack = reinterpret_cast<const std::uint64_t*>(c.Rsp);
            std::fprintf(stderr, "[rt] crash-stack-raw:");
            for (int i = 0; i < 8; ++i) std::fprintf(stderr, " %016llx", static_cast<unsigned long long>(stack[i]));
            std::fprintf(stderr, "\n");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            std::fprintf(stderr, "[rt] crash-stack-raw: unreadable\n");
        }
    }
    // Diagnostic: the retail frame path reads through 0x100000000 (the synthetic-VA base). Commit one guard page
    // there so a read of that address is a value, not a fault, while the caller is being identified.
    __try {
        void* probe = VirtualAlloc(reinterpret_cast<void*>(0x100000000ull), 0x10000,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        std::fprintf(stderr, "[rt] crash-pad: 0x100000000 -> %p\n", probe);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "[rt] crash-pad: failed\n");
    }
    // Diagnostic: the faulting thread's TEB TLS slots (the console main image reads slot 0 directly).
    __try {
        auto** tls = reinterpret_cast<void**>(__readgsqword(0x58));
        std::fprintf(stderr, "[rt] crash-tls: slots=%p slot0=%p slot1=%p slot2=%p slot3=%p\n",
                     static_cast<void*>(tls), tls ? tls[0] : nullptr, tls ? tls[1] : nullptr,
                     tls ? tls[2] : nullptr, tls ? tls[3] : nullptr);
        if (tls && tls[0]) {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(tls[0], &info, sizeof(info)) == sizeof(info))
                std::fprintf(stderr, "[rt] crash-tls: slot0 region base=%p size=0x%llx state=0x%lx protect=0x%lx\n",
                             info.BaseAddress, static_cast<unsigned long long>(info.RegionSize), info.State,
                             info.Protect);
            else
                std::fprintf(stderr, "[rt] crash-tls: slot0 not mapped\n");
            auto* base = static_cast<unsigned char*>(tls[0]);
            std::fprintf(stderr, "[rt] crash-tls: tls+0x12a8=%p tls+0x12a0=%p tls+0x12b0=%p\n",
                         *reinterpret_cast<void**>(base + 0x12a8), *reinterpret_cast<void**>(base + 0x12a0),
                         *reinterpret_cast<void**>(base + 0x12b0));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "[rt] crash-tls: unreadable\n");
    }
    void* frames[32] = {};
    const USHORT count = CaptureStackBackTrace(0, 32, frames, nullptr);
    for (USHORT i = 0; i < count; ++i) {
        HMODULE frame_host = nullptr;
        char frame_module[MAX_PATH] = {};
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(frames[i]), &frame_host) &&
            frame_host)
            GetModuleFileNameA(frame_host, frame_module, MAX_PATH);
        const char* slash = std::strrchr(frame_module, '\\');
        std::fprintf(stderr, "[rt] crash-stack %u: %s+0x%llx\n", i, slash ? slash + 1 : frame_module,
                     frame_host ? static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(frames[i]) -
                                                                  reinterpret_cast<uintptr_t>(frame_host))
                                : 0ull);
    }
    std::fflush(stderr);
    // The retail frame path reads the per-thread context pointer at 0x100000000 (4 GiB): its TLS block is laid out
    // so the pointer field lands exactly at 4 GiB. This thread's own TLS block already holds that pointer at
    // +0x12a8, so put it in the slot the title reads, then let the faulting instruction run again against it.
    // Diagnostic: the A8 render-target format assert (title RVA 0xCC2936). The format is supported by the layer but
    // the title's own info switch still traps; step over the int3 so the next real stop is visible.
    if (r.ExceptionCode == 0x80000003 && info->ContextRecord &&
        info->ContextRecord->Rip == 0x140CC2936ull) {
        static std::atomic<int> skipped_format{0};
        if (skipped_format.fetch_add(1) < 64) {
            std::fprintf(stderr, "[rt] format-int3: rbp=%p r10=%p r13=%p r14=%p rsi=%p rdi=%p\n",
                         reinterpret_cast<void*>(info->ContextRecord->Rbp),
                         reinterpret_cast<void*>(info->ContextRecord->R10),
                         reinterpret_cast<void*>(info->ContextRecord->R13),
                         reinterpret_cast<void*>(info->ContextRecord->R14),
                         reinterpret_cast<void*>(info->ContextRecord->Rsi),
                         reinterpret_cast<void*>(info->ContextRecord->Rdi));
            __try {
                const auto rsp = static_cast<std::uint64_t>(info->ContextRecord->Rsp);
                const auto caller_rsi = *reinterpret_cast<const std::uint64_t*>(rsp + 0x48);
                const auto holder = caller_rsi ? *reinterpret_cast<const std::uint64_t*>(caller_rsi + 0x60) : 0;
                const auto holder_vt = holder ? *reinterpret_cast<const std::uint64_t*>(holder) : 0;
                std::fprintf(stderr, "[rt] format-object: caller_rsi=%p holder=%p holder_vtable=%p\n",
                             reinterpret_cast<void*>(caller_rsi), reinterpret_cast<void*>(holder),
                             reinterpret_cast<void*>(holder_vt));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                std::fprintf(stderr, "[rt] format-object: unreadable\n");
            }
            __try {
                const auto* st = reinterpret_cast<const std::uint64_t*>(info->ContextRecord->Rsp);
                std::fprintf(stderr, "[rt] format-stack-raw:");
                for (int i = 0; i < 10; ++i) std::fprintf(stderr, " %016llx", static_cast<unsigned long long>(st[i]));
                std::fprintf(stderr, "\n");
                for (int i = 0; i < 14; ++i) {
                    const std::uint64_t a = st[i];
                    if (a < 0x10000) continue;
                    HMODULE holder = nullptr;
                    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                           reinterpret_cast<LPCSTR>(a), &holder) &&
                        holder) {
                        char name[MAX_PATH] = {};
                        GetModuleFileNameA(holder, name, MAX_PATH);
                        const char* slash = std::strrchr(name, '\\');
                        std::fprintf(stderr, "[rt] format-frame %d: %s+0x%llx\n", i, slash ? slash + 1 : name,
                                     static_cast<unsigned long long>(a - reinterpret_cast<std::uint64_t>(holder)));
                    } else if (a >= 0x140000000ull && a < 0x150000000ull) {
                        std::fprintf(stderr, "[rt] format-frame %d: game+0x%llx\n", i,
                                     static_cast<unsigned long long>(a - 0x140000000ull));
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                std::fprintf(stderr, "[rt] format-stack-raw: unreadable\n");
            }
            info->ContextRecord->Rip += 1;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    // An unknown console method reached through a vtable with no entry at the called offset: skip the call and
    // answer S_OK (RAX = 0), popping its return address. Bounded and logged, so the next real stop is visible.
    if (r.ExceptionCode == 0xC0000005 && info->ContextRecord && info->ContextRecord->Rip == 0) {
        static std::atomic<int> skipped{0};
        const auto ret = *reinterpret_cast<const std::uint64_t*>(info->ContextRecord->Rsp);
        if (ret >= 0x140000000ull && ret < 0x150000000ull && skipped.fetch_add(1) < 16) {
            std::fprintf(stderr, "[rt] nullcall-skip: return=%p rcx=%p rdx=%p\n",
                         reinterpret_cast<void*>(ret),
                         reinterpret_cast<void*>(info->ContextRecord->Rcx),
                         reinterpret_cast<void*>(info->ContextRecord->Rdx));
            info->ContextRecord->Rip = ret;
            info->ContextRecord->Rsp += 8;
            info->ContextRecord->Rax = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (r.ExceptionCode == 0xC0000005 && access == reinterpret_cast<void*>(0x100000000ull)) {
        __try {
            VirtualAlloc(reinterpret_cast<void*>(0x100000000ull), 0x1000, MEM_COMMIT, PAGE_READWRITE);
            auto** tls = reinterpret_cast<void**>(__readgsqword(0x58));
            void* context = nullptr;
            if (tls && tls[0]) context = *reinterpret_cast<void**>(static_cast<unsigned char*>(tls[0]) + 0x12a8);
            *reinterpret_cast<void**>(0x100000000ull) = context;
            std::fprintf(stderr, "[rt] crash-pad: wrote context %p at 0x100000000\n", context);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            std::fprintf(stderr, "[rt] crash-pad: could not write the context slot\n");
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::filesystem::path image, game_dir, overlay_dir, mods_dir;
    uint32_t archetype_lookup_rva = 0;  // --archetype-lookup RVA[,ARG]: the game's archetype lookup by hash
    int archetype_lookup_arg = 0;
    uint32_t view_mode_getter_rva = 0;  // --view-mode-getter RVA: the game's view mode of a camera context
    bool dry_run = false, init = false, run = false, trace_d3d12 = false;
    std::vector<std::wstring> game_args;  // wide: path::string() throws on a character the code page lacks (RT-84)
    std::wstring trace_file;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--") {
            for (++i; i < argc; ++i) game_args.push_back(argv[i]);
            break;
        }
        if (a == L"--dry-run") dry_run = true;
        else if (a == L"--init") init = true;
        else if (a == L"--run") run = true;
        else if (a == L"--trace-d3d12") trace_d3d12 = true;
        else if (a == L"--trace" && i + 1 < argc) trace_file = argv[++i];
        else if (a == L"--game-dir" && i + 1 < argc) game_dir = argv[++i];
        else if (a == L"--overlay" && i + 1 < argc) overlay_dir = argv[++i];
        else if (a == L"--mods" && i + 1 < argc) mods_dir = argv[++i];
        else if (a == L"--view-mode-getter" && i + 1 < argc) {
            wchar_t* end = nullptr;
            const unsigned long rva = std::wcstoul(argv[++i], &end, 16);
            if (!end || *end || rva == 0) return usage();
            view_mode_getter_rva = static_cast<uint32_t>(rva);
        }
        else if (a == L"--archetype-lookup" && i + 1 < argc) {
            const std::wstring v = argv[++i];
            const auto comma = v.find(L',');
            const std::wstring address = v.substr(0, comma);
            wchar_t* end = nullptr;
            const unsigned long rva = std::wcstoul(address.c_str(), &end, 16);
            if (!end || *end || rva == 0) return usage();
            archetype_lookup_rva = static_cast<uint32_t>(rva);
            if (comma != std::wstring::npos) archetype_lookup_arg = v.substr(comma + 1) == L"1" ? 1 : 0;
        }
        else if (image.empty()) image = a;
        else return usage();
    }
    if (image.empty()) return usage();
    // Exactly one mode: --dry-run --run would otherwise initialise the modules and call the entry point.
    if (dry_run + init + run != 1) return usage();
    // The console folders are fixed once, as absolute paths. A bare image name (`gta6rt --run game.exe` from the
    // game folder) has an empty parent path, which left GAME: with no root; and a relative --game-dir or --overlay
    // would follow the title's later SetCurrentDirectory. If absolute() fails the path stays as given.
    const auto absolute_or_same = [](const std::filesystem::path& p) {
        std::error_code ec;
        std::filesystem::path a = std::filesystem::absolute(p, ec);
        return ec ? p : a;
    };
    game_dir = game_dir.empty() ? absolute_or_same(image).parent_path() : absolute_or_same(game_dir);
    if (!overlay_dir.empty()) overlay_dir = absolute_or_same(overlay_dir);
    // An image without relocations whose range this process already uses (arm64 Wine on macOS) runs in a new
    // process that has the range reserved from the start (base_reservation.h); that process does not do this again.
    if (!rt::base_reservation::inherited())
        if (const auto range = rt::base_reservation::needed(image)) return rt::base_reservation::relaunch(*range);
    // GAME: paths read under --game-dir; whatever a title writes lands in the overlay, never in the package.
    if (overlay_dir.empty()) overlay_dir = game_dir / "overlay";
    rt::fs::configure(game_dir, overlay_dir);
    // Mods (docs/modding.md): <folder of gta6rt.exe>\mods unless --mods names another. Loaded and reported here;
    // the archetype swaps take effect once the game's archetype lookup is hooked for this executable version.
    if (mods_dir.empty()) {
        std::wstring self(32768, L'\0');
        const DWORD n = GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size()));
        if (n && n < self.size()) mods_dir = std::filesystem::path(self.substr(0, n)).parent_path() / L"mods";
    }
    {
        const leonida::mods::LoadResult mods = leonida::mods::load_mods(mods_dir);
        for (const std::string& e : mods.errors) std::fprintf(stderr, "[rt] mods: skipped %s\n", e.c_str());
        for (const auto& m : mods.mods) {
            std::fprintf(stderr, "[rt] mods: %s%s\n", m.name.c_str(), m.enabled ? "" : " (disabled)");
            for (const auto& sw : m.archetype_swaps)
                std::fprintf(stderr, "[rt] mods:   archetype %s (0x%08X) -> %s (0x%08X)\n", sw.from_name.c_str(),
                             sw.from, sw.to_name.c_str(), sw.to);
        }
        leonida::mods::set_active(leonida::mods::ArchetypeSwaps(mods.mods));
        const leonida::mods::CameraView camera = leonida::mods::camera_of(mods.mods);
        leonida::mods::set_active_camera(camera);
        if (camera.first_person)
            std::fprintf(stderr, "[rt] mods: first-person view (value %u) for %s%s\n", camera.first_person_value,
                         camera.contexts.empty() ? "every context" : "the listed contexts",
                         view_mode_getter_rva ? "" : "; not applied: no --view-mode-getter RVA for this executable");
        if (leonida::mods::active().size())
            std::fprintf(stderr, archetype_lookup_rva ? "[rt] mods: %zu archetype swap(s) loaded\n"
                                 : "[rt] mods: %zu archetype swap(s) loaded; not applied: no --archetype-lookup RVA for "
                                   "this executable (docs/modding.md)\n", leonida::mods::active().size());
    }
    rt::d3d12_trace::set_enabled(trace_d3d12);
    AddVectoredExceptionHandler(1, &crash_logger);
    if (int trace_error = 0; !trace_file.empty() && !rt::startup_trace::open(trace_file.c_str(), &trace_error)) {
        std::fprintf(stderr, trace_error == EEXIST ? "error: the trace file already exists; --trace only creates a new file\n"
                                                   : "error: cannot create the trace file\n");
        return 2;
    }
    // The console's Zen 2 instructions this CPU may lack (docs/cpu_features.md): emulated on #UD. Installed after the
    // trace's handler so it runs first, and an emulated instruction is not recorded as an exception.
    if (const auto host = rt::cpu_emulation::detect_host(); !host.sse4a || !host.clzero || !host.monitorx || !host.clwb)
        std::fprintf(stderr, "[rt] cpu: this CPU lacks%s%s%s%s; the game's uses are emulated (docs/cpu_features.md)\n",
                     host.sse4a ? "" : " SSE4a", host.clzero ? "" : " CLZERO", host.monitorx ? "" : " MONITORX",
                     host.clwb ? "" : " CLWB");
    if (!rt::cpu_emulation::install())
        std::fprintf(stderr, "[rt] cpu: AddVectoredExceptionHandler failed (error %lu); instructions this CPU lacks "
                             "will stop the game\n", GetLastError());

    try {
        rt::Loader loader(game_dir);
        rt::Module& main_module = loader.load(image);  // maps, binds and installs TLS; runs no image code
        // The mods' archetype swaps (docs/modding.md): hooked here, before any image code runs, when the lookup's RVA
        // for this executable is given. The count of redirected calls shows whether the RVA is the real lookup.
        if (view_mode_getter_rva) {
            const auto r = leonida::hooks::hook_image_results(main_module.base, view_mode_getter_rva,
                                                              &leonida::mods::override_view_mode);
            if (r.ok)
                std::fprintf(stderr, "[rt] mods: view-mode getter at RVA 0x%X hooked: %zu direct call(s) redirected\n",
                             view_mode_getter_rva, r.redirected);
            else
                std::fprintf(stderr, "[rt] mods: view-mode getter at RVA 0x%X not hooked: %s\n", view_mode_getter_rva,
                             r.error);
        }
        if (archetype_lookup_rva) {
            const auto r = leonida::hooks::hook_image_calls(
                main_module.base, archetype_lookup_rva,
                [](uint32_t hash) { return leonida::mods::active().remap(hash); }, archetype_lookup_arg);
            if (r.ok)
                std::fprintf(stderr, "[rt] mods: archetype lookup at RVA 0x%X hooked (argument %d): %zu direct "
                                     "call(s) redirected\n", archetype_lookup_rva, archetype_lookup_arg, r.redirected);
            else
                std::fprintf(stderr, "[rt] mods: archetype lookup at RVA 0x%X not hooked: %s\n", archetype_lookup_rva,
                             r.error);
        }
        if (run) rt::process::set_command_line(image.filename().wstring(), game_args);
        if (init || run) {
            loader.initialise();  // TLS callbacks, then DllMain(DLL_PROCESS_ATTACH) for DLLs
            std::printf("%zu module(s) initialised\n", loader.modules().size());
        }
        int unimplemented = 0, unimplemented_hresult = 0;
        for (auto* m : loader.modules()) {
            std::map<rt::Binding, int> counts;
            for (auto& r : m->imports) counts[r.binding]++;
            std::printf("%-36s base=%p%s size=%u entry=+%#x  shim=%d host=%d module=%d unimplemented=%d\n",
                        m->name.c_str(), m->base, m->relocated ? " (relocated)" : "", m->size, m->entry_rva,
                        counts[rt::Binding::Shim], counts[rt::Binding::Host], counts[rt::Binding::Module],
                        counts[rt::Binding::Unimplemented]);
            for (auto& r : m->imports)
                if (r.binding == rt::Binding::Unimplemented || r.binding == rt::Binding::Shim) {
                    const bool missing = r.binding == rt::Binding::Unimplemented;
                    const bool hresult =
                        missing && rt::shims::classify_import(r.dll, r.name) == rt::shims::ReturnClass::HResult;
                    std::printf("    %-13s %s!%s%s\n", binding_name(r.binding), r.dll.c_str(), r.name.c_str(),
                                hresult ? "  [returns HRESULT]" : "");
                    unimplemented += missing;
                    unimplemented_hresult += hresult;
                }
        }
        std::printf("%zu module(s) mapped, %d unimplemented import(s)\n", loader.modules().size(), unimplemented);
        std::printf("unimplemented by return policy: hresult=%d other=%d\n", unimplemented_hresult,
                    unimplemented - unimplemented_hresult);
        if (std::getenv("LEONIDA_HEAP_PROBE")) {
            std::fprintf(stderr, "[rt] heap-probe: after mapping\n");
            std::fflush(stderr);
            const BOOL ok = HeapValidate(reinterpret_cast<HANDLE>(_get_heap_handle()), 0, nullptr);
            std::fprintf(stderr, "[rt] heap-probe: after mapping ok=%d\n", ok);
            std::fflush(stderr);
        }
        if (!run) {
            rt::startup_trace::event("exit", "\"code\":0");
            return 0;
        }
        if (!main_module.entry_rva) {
            std::fprintf(stderr, "error: %s has no entry point\n", main_module.name.c_str());
            return 1;
        }
        const std::wstring paths = L"console paths: GAME: -> " + game_dir.native() + L", writes -> " + overlay_dir.native();
        const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode;
        bool printed = false;
        if (GetConsoleMode(out, &mode)) {
            std::fflush(stdout);
            const std::wstring line = paths + L"\r\n";
            DWORD written;
            printed = WriteConsoleW(out, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) != FALSE;
        }
        if (!printed) {
            const auto game = game_dir.u8string();
            const auto overlay = overlay_dir.u8string();
            std::printf("console paths: GAME: -> %s, writes -> %s\n",
                        reinterpret_cast<const char*>(game.c_str()), reinterpret_cast<const char*>(overlay.c_str()));
        }
        std::printf("running %s\n", main_module.name.c_str());
        std::fflush(stdout);
        const int code = rt::process::run_entry(main_module.base + main_module.entry_rva);
        std::fflush(stdout);
        std::printf("game exited with code %d\n", code);
        rt::shims::report_called_unimplemented();
        rt::startup_trace::event("exit", "\"code\":" + std::to_string(code));
        std::fflush(stdout);
        std::fflush(stderr);
        // Not `return`: a normal host exit runs the CRT's atexit table, which the game shares with gta6rt (its
        // handlers would run against a game that has stopped) and whose last word decides the exit status.
        // ExitProcess also skips atexit, so the TLS clone cleanup registered there is run here instead.
        rt::cleanup_tls_clones();
        ExitProcess(static_cast<UINT>(code));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        rt::startup_trace::event("error", "\"what\":" + rt::startup_trace::quote(e.what()));
        return 1;
    }
}
