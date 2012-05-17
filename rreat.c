/*

This file is part of RREAT, an Open Source Reverse Engineering Project.

RREAT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

RREAT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with RREAT.  If not, see <http://www.gnu.org/licenses/>.

*/
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include "rreat.h"

#define assert(expr) if((expr) == 0) EXITERR("%s", #expr)
#define raise(fmt, ...) EXITERR(fmt, ##__VA_ARGS__)

#define EXITERR(msg, ...) _rreat_exit_error(__FUNCTION__, __LINE__, \
        msg, ##__VA_ARGS__)

// _MSC_VER seems to be a good indicator for the MSVC compiler, see also
// http://msdn.microsoft.com/en-us/library/b0084kay(v=vs.80).aspx
// but I think __MSVC__ is easier to read.
#ifdef _MSC_VER
#define __MSVC__
#endif

#ifdef __MSVC__
#define NORETURN __declspec(noreturn)
#else
#define NORETURN __attribute__((noreturn))
#endif

static HMODULE g_kernel32;
static HMODULE g_ntdll;

#ifdef __MSVC__
static HMODULE g_dbghelp;
#endif

// rounds v up to the next highest power of 2
// http://www-graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
static unsigned long roundup2(unsigned long v)
{
    v--, v |= v >> 1, v |= v >> 2, v |= v >> 4;
    return v |= v >> 8, v |= v >> 16, ++v;
}

#ifndef __MSVC__
static inline addr_t __readfsdword(unsigned long index)
{
    addr_t ret;
    __asm__("movl %%fs:(%1), %0" : "=r" (ret) : "r" (index));
    return ret;
}
#endif

static inline unsigned long MIN(unsigned long a, unsigned long b)
{
    return a < b ? a : b;
}

#ifdef __MSVC__

// credits go to:
// http://stackoverflow.com/questions/5693192/win32-backtrace-from-c-code
void _rreat_backtrace(void)
{
    void *stack[32]; SYMBOL_INFO *symbol; int frames;
    char buf[sizeof(SYMBOL_INFO) + 256];

    static USHORT (WINAPI *pCaptureStackBackTrace)(ULONG FramesToSkip,
        ULONG FramesToCapture, PVOID *BackTrace, PULONG BackTraceHash);

    static BOOL (WINAPI *pSymInitialize)(HANDLE hProcess,
        const char *UserSearchPath, BOOL fInvadeProcess);

    static BOOL (WINAPI *pSymCleanup)(HANDLE hProcess);

    static BOOL (WINAPI *pSymFromAddr)(HANDLE hProcess, DWORD64 Address,
        PDWORD64 Displacement, PSYMBOL_INFO Symbol);

    if(pSymInitialize == NULL) {
        pCaptureStackBackTrace = (USHORT(WINAPI *)(ULONG, ULONG, PVOID *,
            PULONG)) GetProcAddress(g_kernel32, "RtlCaptureStackBackTrace");

        pSymInitialize = (BOOL(WINAPI *)(HANDLE, const char *, BOOL))
            GetProcAddress(g_dbghelp, "SymInitialize");

        pSymCleanup = (BOOL(WINAPI *)(HANDLE)) GetProcAddress(g_dbghelp,
            "SymCleanup");

        pSymFromAddr = (BOOL(WINAPI *)(HANDLE, DWORD64, PDWORD64,
            PSYMBOL_INFO)) GetProcAddress(g_dbghelp, "SymFromAddr");
    }

    pSymInitialize(GetCurrentProcess(), NULL, TRUE);

    frames = pCaptureStackBackTrace(0, 32, stack, NULL);
    symbol = (SYMBOL_INFO *) buf;

    memset(symbol, 0, sizeof(buf));
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = 255;

    for (int i = 0; i < frames; i++) {
        pSymFromAddr(GetCurrentProcess(), (DWORD64) stack[i], NULL, symbol);
        printf("%s (0x%08x)\n", symbol->Name, symbol->Address);
    }

    pSymCleanup(GetCurrentProcess());
}

#else

void _rreat_backtrace()
{
}

#endif

static NORETURN void _rreat_exit_error(const char *func, int line,
    const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    fprintf(stderr, "%s:%d (%lu) -> ", func, line, GetLastError());
    vfprintf(stderr, msg, args);
    va_end(args);
    _rreat_backtrace();
    // TODO: cleanup
    ExitProcess(0);
}

void rreat_init()
{
    g_kernel32 = GetModuleHandle("kernel32.dll");
    g_ntdll = GetModuleHandle("ntdll.dll");
    assert(g_kernel32 != NULL && g_ntdll != NULL);

#ifdef __MSVC__
    g_dbghelp = LoadLibrary("dbghelp.dll");
    assert(g_dbghelp != NULL);
#endif
}

//
// RREAT Memory API
//

addr_t rreat_alloc(rreat_t *rr, unsigned long size, unsigned long flags)
{
    static const unsigned long table[8] = {
        /*     */ 0,
        /* R   */ PAGE_READONLY,
        /*  W  */ PAGE_READWRITE,
        /* RW  */ PAGE_READWRITE,
        /*   X */ PAGE_EXECUTE,
        /* R X */ PAGE_EXECUTE_READ,
        /*  WX */ PAGE_EXECUTE_READWRITE,
        /* RWX */ PAGE_EXECUTE_READWRITE,
    };

    assert(flags != 0 && flags < sizeofarray(table));

    addr_t ret = (addr_t) VirtualAllocEx(rr->handle, NULL, roundup2(size),
        MEM_COMMIT | MEM_RESERVE, table[flags]);
    assert(ret != 0);
    return ret;
}

void rreat_free(rreat_t *rr, addr_t addr)
{
    assert(VirtualFreeEx(rr->handle, (void *) addr, 0, MEM_RELEASE));
}

void rreat_write(rreat_t *rr, addr_t addr, const void *src, unsigned long size)
{
    unsigned long bytes;
    assert(WriteProcessMemory(rr->handle, (void *) addr, src, size, &bytes));
    assert(bytes == size);
}

void rreat_read(rreat_t *rr, addr_t addr, void *dest, unsigned long size)
{
    unsigned long bytes;
    assert(ReadProcessMemory(rr->handle, (void *) addr, dest, size, &bytes));
    assert(bytes == size);
}

//
// RREAT Debugger API
//

void rreat_context_get(rreat_t *rr, int thread_id, CONTEXT *ctx,
    unsigned long flags)
{
    rreat_thread_t *t = rreat_thread_by_id(rr, thread_id);
    ctx->ContextFlags = flags;
    assert(GetThreadContext(t->handle, ctx));
}

void rreat_context_set(rreat_t *rr, int thread_id, CONTEXT *ctx)
{
    rreat_thread_t *t = rreat_thread_by_id(rr, thread_id);
    assert(SetThreadContext(t->handle, ctx));
}

addr_t rreat_ip_get(rreat_t *rr, int thread_id)
{
    CONTEXT ctx;
    rreat_context_get(rr, thread_id, &ctx, CONTEXT_CONTROL);
    return ctx.Eip;
}

void rreat_ip_set(rreat_t *rr, int thread_id, addr_t addr)
{
    CONTEXT ctx;
    rreat_context_get(rr, thread_id, &ctx, CONTEXT_CONTROL);
    ctx.Eip = addr;
    rreat_context_set(rr, thread_id, &ctx);
}

void rreat_ip_add(rreat_t *rr, int thread_id, int delta)
{
    CONTEXT ctx;
    rreat_context_get(rr, thread_id, &ctx, CONTEXT_CONTROL);
    ctx.Eip += delta;
    rreat_context_set(rr, thread_id, &ctx);
}

// create a new process object
rreat_t *rreat_process_init(const char *filename, char *cmdline)
{
    STARTUPINFO si = {0}; PROCESS_INFORMATION pi = {0};
    assert(CreateProcess(filename, cmdline, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi));
    rreat_t *rr = (rreat_t *) calloc(1, sizeof(rreat_t));
    assert(rr != NULL);

    rr->process_id = pi.dwProcessId;
    rr->handle = pi.hProcess;
    rreat_thread_init(rr, pi.hThread);
    return rr;
}

// attach to a process
rreat_t *rreat_process_attach(unsigned long pid, unsigned long desired_access)
{
    rreat_t *rr = (rreat_t *) calloc(1, sizeof(rreat_t));
    assert(rr != NULL);

    rr->process_id = pid;
    rr->handle = OpenProcess(desired_access, FALSE, pid);
    assert(rr->handle != NULL);
    return rr;
}

// open a handle to each thread, only useful after attaching to a process
void rreat_attach_all_threads(rreat_t *rr)
{
    // TODO: ...
}

void rreat_process_terminate(rreat_t *rr, unsigned int exit_code)
{
    assert(TerminateProcess(rr->handle, exit_code));
}

// create a new thread object (returns thread id)
int rreat_thread_init(rreat_t *rr, HANDLE handle)
{
    int newsize = roundup2(rr->thread_count + 1);
    if(roundup2(rr->thread_count) != newsize) {
        rr->threads = (rreat_thread_t *) realloc(rr->threads, newsize);
        assert(rr->threads != NULL);
    }
    rreat_thread_t *t = &rr->threads[rr->thread_count];
    t->thread_id = rr->thread_count++;
    t->handle = handle;
    return rr->thread_count - 1;
}

// resume a thread
void rreat_thread_resume(rreat_t *rr, int thread_id)
{
    rreat_thread_t *t = rreat_thread_by_id(rr, thread_id);
    assert(ResumeThread(t->handle) != -1);
}

// suspend a thread
void rreat_thread_suspend(rreat_t *rr, int thread_id)
{
    rreat_thread_t *t = rreat_thread_by_id(rr, thread_id);
    assert(SuspendThread(t->handle) != -1);
}

// get a thread object by its id
rreat_thread_t *rreat_thread_by_id(rreat_t *rr, int thread_id)
{
    assert(thread_id >= 0 && thread_id < rr->thread_count);
    return &rr->threads[thread_id];
}

// dump a series of pages
void rreat_dump_module(rreat_t *rr, addr_t base_addr, const char *filename)
{
    MODULEINFO mi;
    assert(GetModuleInformation(rr->handle, (HMODULE) base_addr, &mi,
        sizeof(mi)));
    void *mem = VirtualAlloc(NULL, mi.SizeOfImage, MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    assert(mem != NULL);
    rreat_read(rr, (addr_t) mi.lpBaseOfDll, mem, mi.SizeOfImage);
    // for now let's hope our binary doesn't destroy the PE headers
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *) mem;
    if(dos_header->e_lfanew >= 0 &&
            (unsigned long) dos_header->e_lfanew < mi.SizeOfImage) {
        IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)(
            (unsigned char *) mem + dos_header->e_lfanew);
        // needs more checking.
        IMAGE_SECTION_HEADER *section_header = (IMAGE_SECTION_HEADER *)(
            (unsigned char *) &nt_headers->OptionalHeader +
            nt_headers->FileHeader.SizeOfOptionalHeader);
        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections;
                i++, section_header++) {
            // IDA will think the binary is still in raw-offset mode
            // so we have to set the raw offset & raw size to the virtual
            // address equivalents
            section_header->PointerToRawData = section_header->VirtualAddress;
            section_header->SizeOfRawData = section_header->Misc.VirtualSize;
        }
    }
    FILE *fp = fopen(filename, "wb");
    assert(fp != NULL);
    fwrite(mem, 1, mi.SizeOfImage, fp);
    fclose(fp);
    assert(VirtualFree(mem, 0, MEM_RELEASE));
}

// attach JIT Debugger to Process
void rreat_jitdbg_attach(rreat_t *rr)
{
    char path[MAX_PATH];
    _snprintf(path, sizeofarray(path), RREAT_JITDEBUGGER, rr->process_id);
    STARTUPINFO si = {0}; PROCESS_INFORMATION pi = {0};
    assert(CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si,
        &pi));
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

// places the thread in a while(1) loop
// with a jmp behind it that will point to the original address
void rreat_thread_while1(rreat_t *rr, int thread_id)
{
    CONTEXT ctx;
    rreat_context_get(rr, thread_id, &ctx, CONTEXT_FULL);
    unsigned char code[7] = {0xeb, 0xfe, 0xe9};
    addr_t addr = rreat_alloc(rr, 7, RREAT_RWX);
    *(addr_t *) &code[3] = ctx.Eip - addr - 5 - 2;
    ctx.Eip = addr;
    rreat_context_set(rr, thread_id, &ctx);
    rreat_write(rr, addr, code, sizeof(code));
    rreat_thread_resume(rr, thread_id);
}

// waits until the thread hits the given address
int rreat_thread_wait_for_address(rreat_t *rr, int thread_id, addr_t addr,
        int milliseconds)
{
    // do a check before-hand, so we might not have to wait a millisecond
    if(rreat_ip_get(rr, thread_id) == addr) return RREAT_SUCCESS;

    unsigned long start = GetTickCount();
    while (start + milliseconds > GetTickCount()) {
        rreat_thread_resume(rr, thread_id);
        Sleep(1);
        rreat_thread_suspend(rr, thread_id);
        if(rreat_ip_get(rr, thread_id) == addr) return RREAT_SUCCESS;
    }
    return RREAT_WAIT;
}

// wait for the thread
int rreat_process_wait_for_address_insert_while1(rreat_t *rr, int thread_id,
    addr_t addr, int milliseconds)
{
    unsigned char backup[2];
    rreat_read(rr, addr, backup, sizeof(backup));
    rreat_write(rr, addr, "\xeb\xfe", 2);
    int ret = rreat_thread_wait_for_address(rr, thread_id, addr, milliseconds);
    rreat_write(rr, addr, backup, sizeof(backup));
    return ret;
}

//
// RREAT Simulate API
//

// init new object
rreat_simulate_t *rreat_simulate_init(rreat_t *rr)
{
    rreat_simulate_t *ret = (rreat_simulate_t *)
        calloc(1, sizeof(rreat_simulate_t));
    assert(ret != NULL);
    ret->_rr = rr;
    return ret;
}

// assign start and end address, `wait' will run until `end' is hit.
void rreat_simulate_address(rreat_simulate_t *rr, addr_t start, addr_t end)
{
    assert(end - start >= 5);
    rr->start = start;
    rr->end = end;
}

// apply in the process
void rreat_simulate_apply(rreat_simulate_t *sim)
{
    int size = sim->end - sim->start;
    sim->_mem = rreat_alloc(sim->_rr, size + 4, RREAT_RWX);
    sim->_backup = malloc(size);
    // read original code
    rreat_read(sim->_rr, sim->start, sim->_backup, size);
    // write new code with a while(1) loop before and after the code
    rreat_write(sim->_rr, sim->_mem, "\xeb\xfe", 2);
    rreat_write(sim->_rr, sim->_mem + 2, sim->_backup, size);
    rreat_write(sim->_rr, sim->_mem + size + 2, "\xeb\xfe", 2);
    // write detour jmp
    unsigned char jmp[5] = {0xe9};
    *(addr_t *) &jmp[1] = sim->_mem - sim->start - 5;
    rreat_write(sim->_rr, sim->start, jmp, sizeof(jmp));
}

// wait for a certain thread to finish this `simulation'
int rreat_simulate_run(rreat_simulate_t *sim, int thread_id, int milliseconds)
{
    unsigned long start = GetTickCount();

    // wait until we actually reach our special code
    assert(rreat_thread_wait_for_address(sim->_rr, thread_id,
        sim->_mem, milliseconds) == RREAT_SUCCESS);

    // move past the while(1) instruction
    rreat_ip_add(sim->_rr, thread_id, 2);

    // restore the original code..
    rreat_write(sim->_rr, sim->start, sim->_backup, sim->end - sim->start);

    // now wait till it finishes (don't include the time we have already been
    // processing, assume we have time left)
    milliseconds = start + milliseconds - GetTickCount();
    return rreat_thread_wait_for_address(sim->_rr, thread_id,
        sim->_mem + sim->end - sim->start, milliseconds);
}

// restore the thread to the real address
void rreat_simulate_restore(rreat_simulate_t *sim, int thread_id)
{
    // restore eip
    rreat_ip_set(sim->_rr, thread_id, sim->end);
}

// free simulate api
void rreat_simulate_free(rreat_simulate_t *sim)
{
    rreat_free(sim->_rr, sim->_mem);
    free(sim->_backup);
    free(sim);
}

// single-threaded blocking `simulate' event.
void rreat_simulate_single(rreat_t *rr, addr_t start, addr_t end,
    int milliseconds, int thread_id)
{
    rreat_simulate_t *sim = rreat_simulate_init(rr);
    rreat_simulate_address(sim, start, end);
    rreat_simulate_apply(sim);
    rreat_thread_resume(rr, thread_id);
    assert(rreat_simulate_run(sim, thread_id, milliseconds) == RREAT_SUCCESS);
    rreat_simulate_restore(sim, thread_id);
    rreat_simulate_free(sim);
}

//
// RREAT Debug Register API
//

static void _set_bits(unsigned long *value, int offset, int bits, int newval)
{
    unsigned long mask = (1 << bits) - 1;
    *value = (*value & ~(mask << offset)) | (newval << offset);
}

rreat_hwbp_t *rreat_debugreg_trap(rreat_t *rr, int thread_id, int hwbp_index,
    addr_t addr, int flags, int size)
{
    static const unsigned char table_flags[5] = {
        /*     */ 0xff, // invalid
        /* R   */ 3,
        /*  W  */ 1,
        /* RW  */ 3,
        /*   X */ 0,
    };
    static const unsigned char table_size[9] = {
        /* 0 */ 0xff,
        /* 1 */ 0,    // 1 byte
        /* 2 */ 1,    // 2 bytes
        /* 3 */ 0xff,
        /* 4 */ 3,    // 4 bytes
        /* 5 */ 0xff,
        /* 6 */ 0xff,
        /* 7 */ 0xff,
        /* 8 */ 2,    // 8 bytes
    };
    assert(hwbp_index >= 0 && hwbp_index < 4);
    assert(flags > 0 && flags < sizeofarray(table_flags));
    assert(size > 0 && size < sizeofarray(table_size) &&
        table_size[size] != 0xff);

    rreat_hwbp_t *hwbp = (rreat_hwbp_t *) calloc(1, sizeof(rreat_hwbp_t));
    assert(hwbp != NULL);

    CONTEXT ctx;
    rreat_context_get(rr, thread_id, &ctx, CONTEXT_DEBUG_REGISTERS);
    // enable this Debug Register in bits 0..7
    _set_bits(&ctx.Dr7, hwbp_index * 2, 2, 1);
    // set the `type' in bits 16..23
    _set_bits(&ctx.Dr7, 16 + hwbp_index * 2, 2, table_flags[flags]);
    // set the `size' in bits 24..31
    _set_bits(&ctx.Dr7, 24 + hwbp_index * 2, 2, table_size[size]);
    // set the trap address
    ((addr_t *) &ctx.Dr0)[hwbp_index] = addr;
    rreat_context_set(rr, thread_id, &ctx);

    hwbp->addr = addr;
    hwbp->flags = flags;
    hwbp->size = size;
    return hwbp;
}

void rreat_debugreg_enable(rreat_t *rr, int thread_id, int hwbp_index)
{
    assert(hwbp_index >= 0 && hwbp_index < 4);

    CONTEXT ctx;
    rreat_context_get(rr, thread_id, &ctx, CONTEXT_DEBUG_REGISTERS);
    // set the field in the 0..7 bits
    _set_bits(&ctx.Dr7, hwbp_index * 2, 2, 1);
    rreat_context_set(rr, thread_id, &ctx);
}

void rreat_debugreg_disable(rreat_t *rr, int thread_id, int hwbp_index)
{
    assert(hwbp_index >= 0 && hwbp_index < 4);

    CONTEXT ctx;
    rreat_context_get(rr, thread_id, &ctx, CONTEXT_DEBUG_REGISTERS);
    // clear the field in the 0..7 bits
    _set_bits(&ctx.Dr7, hwbp_index * 2, 2, 0);
    rreat_context_set(rr, thread_id, &ctx);
}

//
// RREAT Vectored Exception Handler API
//

rreat_veh_t *rreat_veh_install(rreat_t *rr, addr_t addr, int first_handler)
{
    unsigned char install[] = {
        0xb8, 0x00, 0x00, 0x00, 0x00, // AddVectoredExceptionHandler() address
        0x68, 0x00, 0x00, 0x00, 0x00, // handler address
        0x6a, first_handler != 0,     // `first handler' ?
        0xff, 0xd0,                   // call AddVectoredExceptionHandler()
        0xa3, 0x00, 0x00, 0x00, 0x00, // store the exception handler handle
        0xc3,
    };

    unsigned char remove[] = {
        0xb8, 0x00, 0x00, 0x00, 0x00, // RemoveVectoredExceptionHandler() addr
        0x68, 0x00, 0x00, 0x00, 0x00, // handle to exception handler
        0xff, 0xd0,                   // call RemoveVectoredExceptionHandler()
        0xc3,
    };

    rreat_veh_t *veh = (rreat_veh_t *) calloc(1, sizeof(rreat_veh_t));

    addr_t mem = rreat_alloc(rr, sizeof(install) + sizeof(remove), RREAT_RWX);

    // store address of AddVectoredExceptionHandler
    *(addr_t *) &install[1] = (addr_t) GetProcAddress(g_kernel32,
        "AddVectoredExceptionHandler");

    // store address of the exception handler
    *(addr_t *) &install[6] = addr;

    // store the address of RemoveVectoredExceptionHandler
    *(addr_t *) &remove[1] = (addr_t) GetProcAddress(g_kernel32,
        "RemoveVectoredExceptionHandler");

    // store the address where to write the handle to the exception handler
    // this can be used later to uninstall the exception handler
    *(addr_t *) &install[15] = mem + sizeof(install) + 6;

    veh->mem = mem;
    veh->remove_handler = (LPTHREAD_START_ROUTINE)(mem + sizeof(install));

    // write the two shellcodes
    rreat_write(rr, mem, install, sizeof(install));
    rreat_write(rr, mem + sizeof(install), remove, sizeof(remove));

    // now install the handler
    HANDLE thread = CreateRemoteThread(rr->handle, NULL, 0,
        (LPTHREAD_START_ROUTINE) mem, NULL, 0, NULL);
    assert(thread != INVALID_HANDLE_VALUE);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    return veh;
}

void rreat_veh_uninstall(rreat_t *rr, rreat_veh_t *veh)
{
    // call the remove handler
    HANDLE thread = CreateRemoteThread(rr->handle, NULL, 0,
        veh->remove_handler, NULL, 0, NULL);
    assert(thread != INVALID_HANDLE_VALUE);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    // free memory
    rreat_free(rr, veh->mem);
    free(veh);
}

//
// RREAT Detour API
//

typedef void (*_rreat_detour_type_t)(rreat_t *rr, rreat_detour_t *detour,
    addr_t addr, addr_t payload);

// places a regular "jmp payload" instruction at `addr'.
static void _rreat_detour_jmp(rreat_t *rr, rreat_detour_t *detour, addr_t addr,
    addr_t payload)
{
    detour->length = 5;
    detour->addr = addr;
    rreat_read(rr, detour->addr, detour->backup, detour->length);

    unsigned char bytes[5] = {0xe9};
    *(addr_t *) &bytes[1] = payload - addr - 5;

    rreat_write(rr, detour->addr, bytes, detour->length);
}

static void _rreat_detour_fpu(rreat_t *rr, rreat_detour_t *detour, addr_t addr,
    addr_t payload)
{
    detour->length = 11;
    detour->addr = addr;
    rreat_read(rr, detour->addr, detour->backup, detour->length);

    detour->_extra_data = rreat_alloc(rr, sizeof(double), RREAT_RW);

    double payload_addr = (double) payload;
    rreat_write(rr, detour->_extra_data, &payload_addr, sizeof(payload_addr));

    unsigned char bytes[] = {
        0x55,                               // push ebp
        0xdd, 0x05, 0x00, 0x00, 0x00, 0x00, // fld qword [_extra_data]
        0xdb, 0x1c, 0xe4,                   // fistp dword [esp]
        0xc3,                               // retn
    };

    *(addr_t *) &bytes[3] = detour->_extra_data;
    rreat_write(rr, addr, &bytes, sizeof(bytes));
}

rreat_detour_t *rreat_detour_address(rreat_t *rr, addr_t addr, addr_t payload,
    int detour_type)
{
    assert(addr != 0 && payload != 0);

    rreat_detour_t *detour = (rreat_detour_t *) malloc(sizeof(rreat_detour_t));
    assert(detour != NULL);

    static const _rreat_detour_type_t detours[] = {
        /* RREAT_DETOUR_JMP */ &_rreat_detour_jmp,
        /* RREAT_DETOUR_FPU */ &_rreat_detour_fpu,
    };

    assert(detour_type >= 0 && detour_type < sizeofarray(detours));

    detour->_extra_data = 0;
    detours[detour_type](rr, detour, addr, payload);
    return detour;
}

void rreat_detour_remove(rreat_t *rr, rreat_detour_t *detour)
{
    rreat_write(rr, detour->addr, detour->backup, detour->length);
    if(detour->_extra_data != 0) {
        rreat_free(rr, detour->_extra_data);
    }
    free(detour);
}

//
// RREAT Generic Syscall Hooking
//

static const char *g_syshook_names[64 * 1024];

static DWORD WINAPI _rreat_syshook_worker(LPVOID _syshook)
{
    rreat_syshook_t *syshook = (rreat_syshook_t *) _syshook;
    // TODO: One Event per Thread (store event handle in TLS)
    while (WaitForSingleObject(syshook->event_local, INFINITE) ==
            WAIT_OBJECT_0) {
        int thread_id = 0;
        static int pre_syscall = 1, syscall_number = 0;
        static addr_t arg_addr = 0;

        rreat_thread_suspend(syshook->_rr, thread_id);

        if(pre_syscall) {
            // wait till the thread hits the infinite loop (this should
            // be instant, but we have to check anyway, because otherwise the
            // stack variabele might be corrupted.)
            assert(rreat_thread_wait_for_address(syshook->_rr, thread_id,
                syshook->handler + 0x38, 100) == RREAT_SUCCESS);

            CONTEXT ctx; unsigned long param[16];
            rreat_context_get(syshook->_rr, thread_id, &ctx, CONTEXT_FULL);

            // edx points to the arguments on the stack
            arg_addr = ctx.Edx;
            rreat_read(syshook->_rr, ctx.Edx, param, sizeof(param));

            // eax is the system call number
            syscall_number = ctx.Eax & 0xffff;
            syshook->callback[syscall_number](syshook, param, thread_id,
                pre_syscall);

            // jump over the infinite loop and execute the actual syscall
            rreat_ip_add(syshook->_rr, thread_id, 2);
            rreat_thread_resume(syshook->_rr, thread_id);
        }
        else {
            assert(rreat_thread_wait_for_address(syshook->_rr, thread_id,
                syshook->handler + 0x63, 100) == RREAT_SUCCESS);

            CONTEXT ctx; unsigned long param[16];
            rreat_context_get(syshook->_rr, thread_id, &ctx, CONTEXT_FULL);
            rreat_read(syshook->_rr, arg_addr, param, sizeof(param));

            syshook->callback[syscall_number](syshook, param, thread_id,
                pre_syscall);

            // jump over the do_not_intervene and notify-event, execute the
            // actual syscall and get a post-event.
            rreat_ip_add(syshook->_rr, thread_id, 2);
            rreat_thread_resume(syshook->_rr, thread_id);
        }
        pre_syscall = !pre_syscall;
    }
    return 0;
}

static void _rreat_syshook_enum_syscalls()
{
    static int first = 1;
    if(first == 0) return;
    first = 0;

    // no boundary checking at all, I assume ntdll is not malicious..
    // besides that, we are in our own process, _should_ be fine..
    BYTE *image = (BYTE *) g_ntdll;
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *) image;
    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)(image +
        dos_header->e_lfanew);
    IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *export_directory = (IMAGE_EXPORT_DIRECTORY *)(
        image + data_directory->VirtualAddress);
    DWORD *address_of_names = (DWORD *)(image +
        export_directory->AddressOfNames);
    DWORD *address_of_functions = (DWORD *)(image +
        export_directory->AddressOfFunctions);
    USHORT *address_of_name_ordinals = (USHORT *)(image +
        export_directory->AddressOfNameOrdinals);
    unsigned long number_of_names = MIN(export_directory->NumberOfFunctions,
        export_directory->NumberOfNames);
    for (unsigned long i = 0; i < number_of_names; i++) {
        const char *name = (const char *)(image + address_of_names[i]);
        unsigned char *addr = image + address_of_functions[
            address_of_name_ordinals[i]];
        if(!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
            // does the signature match?
            // either:   mov eax, syscall_number ; mov ecx, some_value
            // or:       mov eax, syscall_number ; xor ecx, ecx
            if(*addr == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33)) {
                unsigned long syscall_number = *(unsigned long *)(addr + 1);
                g_syshook_names[syscall_number] = name;
            }
        }
    }
}

unsigned short rreat_syshook_syscall_name_to_number(const char *name)
{
    assert(name != NULL);
    assert(!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2));
    for (int i = 0; i < 64 * 1024; i++) {
        if(g_syshook_names[i] != NULL &&
                !strcmp(g_syshook_names[i] + 2, name + 2)) {
            return (unsigned short) i;
        }
    }
    raise("Syscall name `%s' not found.", name);
}

const char *rreat_syshook_syscall_number_to_name(unsigned short number)
{
    return g_syshook_names[number];
}

rreat_syshook_t *rreat_syshook_init(rreat_t *rr)
{
    _rreat_syshook_enum_syscalls();

    // WOW64 support only, at the moment.
    static BOOL (WINAPI *pIsWow64Process)(HANDLE hProcess, BOOL *pbIsWow64);
    if(pIsWow64Process == NULL) {
        pIsWow64Process = (BOOL(WINAPI *)(HANDLE, PBOOL)) GetProcAddress(
            g_kernel32, "IsWow64Process");
        assert(pIsWow64Process != NULL);
    }

    BOOL is_wow64;
    assert(pIsWow64Process(rr->handle, &is_wow64) && is_wow64 != FALSE);

    rreat_syshook_t *ret = (rreat_syshook_t *) malloc(sizeof(rreat_syshook_t));
    assert(ret != NULL);

    ret->_rr = rr;

    // ntdll jumps into 64bit from this address.
    ret->jump_address = __readfsdword(0xc0);

    // store the jump address (we are not interested in the "jmp" part of it.)
    memcpy(ret->far_jump_address, (void *)(ret->jump_address + 1),
        sizeof(ret->far_jump_address));

    // entry for each syscall number
    ret->table = rreat_alloc(rr, 64 * 1024, RREAT_RW);

    // create the event
    ret->event_local = CreateEvent(NULL, FALSE, FALSE, NULL);
    assert(ret->event_local != NULL);

    // duplicate the event, for interprocess communication
    assert(DuplicateHandle(GetCurrentProcess(), ret->event_local, rr->handle,
        &ret->event_remote, 0, FALSE, DUPLICATE_SAME_ACCESS));

    unsigned char bytes[] = {
             //
             // Use the Lookup table to check if we want to intervene with
             // this syscall.
             //

    /* 00 */ 0x60,                               // pushad
    /* 01 */ 0x0f, 0xb7, 0xc0,                   // movzx eax, ax
    /* 04 */ 0x0f, 0xb6, 0x80, 0x00, 0x00, 0x00, // movzx eax, byte [eax+addr]
                   0x00,
    /* 0b */ 0x85, 0xc0,                         // test eax, eax
    /* 0d */ 0x75, 0x08,                         // jnz do_intervene

             //
             // We don't want to intervene with this syscall, perform the
             // original syscall.
             //

    /* 0f */ 0x61,                               // popad
    /* 10 */ 0xea, 0x00, 0x00, 0x00, 0x00, 0x00, // original far jump
                   0x00,

             //
             // We want to intervene with this syscall, notify our parent.
             // This event is called a "pre-event", it's right before the
             // real syscall and allows the parent to inspect and/or modify
             // parameters.
             //

    /* 17 */ 0x6a, 0x00,                         // push 0
    /* 19 */ 0x68, 0x00, 0x00, 0x00, 0x00,       // push notify-event
    /* 1e */ 0xb8, 0x00, 0x00, 0x00, 0x00,       // mov eax, syscall_number
    /* 23 */ 0xb9, 0x07, 0x00, 0x00, 0x00,       // mov ecx, 0x07
    /* 28 */ 0x89, 0xe2,                         // mov edx, esp
    /* 2a */ 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, // far call for SetEvent()
                   0x00,

             //
             // We notified the parent process, restore the stack pointer,
             // followed by restoring the other registers.
             //

    /* 31 */ 0x83, 0xc4, 0x0c,                   // add esp, 0x0c
    /* 34 */ 0x61,                               // popad

             //
             // due to a difference between windows 7 and windows vista we
             // to add 4 to esp, on windows 7 here, for vista, we do nothing
             // here.

    /* 35 */ 0x83, 0xc4, 0x00,                   // add esp, 0x00

             //
             // The parent process will suspend the thread when it's at this
             // infinite loop, so it can alter parameters to the real syscall.
             //

    /* 38 */ 0xeb, 0xfe,                         // while(1);

             //
             // Perform the real syscall.
             //

    /* 3a */ 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

             //
             // For some reason we have to cleanup after this syscall..
             //

    /* 41 */ 0x83, 0xc4, 0x04,                   // add esp, 4

             //
             // Notify the parent process, this time we give it the so-called
             // "post-event" notification, the parent process will be able to
             // inspect and/or modify the return value and/or any output
             // variabeles given through a parameter.
             //

    /* 44 */ 0x60,                               // pushad
    /* 46 */ 0x6a, 0x00,                         // push 0
    /* 47 */ 0x68, 0x00, 0x00, 0x00, 0x00,       // push notify-event
    /* 4c */ 0xb8, 0x00, 0x00, 0x00, 0x00,       // mov eax, syscall_number
    /* 51 */ 0xb9, 0x07, 0x00, 0x00, 0x00,       // mov ecx, 0x07
    /* 56 */ 0x89, 0xe2,                         // mov edx, esp
    /* 58 */ 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, // far call SetEvent()
                   0x00,

             //
             // Again we restore the stack pointer and registers.
             //

    /* 5f */ 0x83, 0xc4, 0x0c,                   // add esp, 0x0c
    /* 62 */ 0x61,                               // popad

             //
             // The parent will wait 'till the thread hits this infinite loop,
             // just like it does at the pre-event.
             //

    /* 63 */ 0xeb, 0xfe,                         // while(1);
    /* 65 */ 0xc3,                               // retn
    };

    // allocate enough memory for the handler
    ret->handler = rreat_alloc(rr, sizeof(bytes), RREAT_RWX);

    // overwrite the address for the far jumps
    memcpy(&bytes[0x11], ret->far_jump_address, sizeof(ret->far_jump_address));
    memcpy(&bytes[0x2b], ret->far_jump_address, sizeof(ret->far_jump_address));
    memcpy(&bytes[0x3b], ret->far_jump_address, sizeof(ret->far_jump_address));
    memcpy(&bytes[0x59], ret->far_jump_address, sizeof(ret->far_jump_address));

    // write address of the table
    *(addr_t *) &bytes[0x07] = ret->table;

    // write the the notify-event handles
    *(HANDLE *) &bytes[0x1a] = ret->event_remote;
    *(HANDLE *) &bytes[0x48] = ret->event_remote;

    *(unsigned long *) &bytes[0x1f] =
        rreat_syshook_syscall_name_to_number("ZwSetEvent");
    *(unsigned long *) &bytes[0x4d] =
        rreat_syshook_syscall_name_to_number("ZwSetEvent");

    // there is a slight difference between Windows 7 and Windows Vista
    // in windows 7 each system call is followed by an `add esp, 4'
    // instruction, therefore we have to add 4 to a few instructions.
    OSVERSIONINFOEX OsVersion = {0};
    OsVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    if(GetVersionEx((OSVERSIONINFO *) &OsVersion) &&
            OsVersion.dwMajorVersion == 6 && OsVersion.dwMinorVersion == 1) {
        bytes[0x33] += 4;
        bytes[0x37] += 4;
        bytes[0x43] += 4;
        bytes[0x61] += 4;
    }

    // clear the entire lookup table
    unsigned char null[64] = {0};
    for (int i = 0; i < 1024; i++) {
        rreat_write(rr, ret->table + 64 * i, null, 64);
    }

    // write the handler
    rreat_write(rr, ret->handler, bytes, sizeof(bytes));

    // write a jump at the original x64 land far jump
    unsigned char jump[5] = {0xe9};
    *(addr_t *) &jump[1] = ret->handler - ret->jump_address - 5;
    rreat_write(rr, ret->jump_address, jump, sizeof(jump));

    // at last, create a thread that will wait for notifications
    ret->thread_handle = CreateThread(NULL, 0, &_rreat_syshook_worker, ret,
        0, NULL);
    assert(ret->thread_handle != INVALID_HANDLE_VALUE);

    return ret;
}

void rreat_syshook_set_hook(rreat_syshook_t *syshook, const char *name,
    rreat_syshook_hook_t hook)
{
    int index = rreat_syshook_syscall_name_to_number(name);

    syshook->callback[index] = hook;

    // set this index in the child
    unsigned char state = 1;
    rreat_write(syshook->_rr, syshook->table + index, &state, sizeof(state));
}

void rreat_syshook_unset_hook(rreat_syshook_t *syshook, const char *name)
{
    int index = rreat_syshook_syscall_name_to_number(name);

    syshook->callback[index] = NULL;

    // unset this index in the child
    unsigned char state = 0;
    rreat_write(syshook->_rr, syshook->table + index, &state, sizeof(state));
}

