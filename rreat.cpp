#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include "rreat.h"

#define assert(expr) if((expr) == 0) EXITERR("%s", #expr)
// #define assert(expr) expr

#define EXITERR(msg, ...) _rreat_exit_error(__FUNCTION__, __LINE__, \
        msg, ##__VA_ARGS__)

HMODULE hKernel32 = GetModuleHandle("kernel32.dll");

// rounds v up to the next highest power of 2
// http://www-graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
static unsigned long roundup2(unsigned long v) {
    v--, v |= v >> 1, v |= v >> 2, v |= v >> 4;
    return v |= v >> 8, v |= v >> 16, ++v;
}

static void _rreat_exit_error(const char *func, int line, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    fprintf(stderr, "%s:%d -> ", func, line);
    vfprintf(stderr, msg, args);
    va_end(args);
    // TODO: cleanup
    ExitProcess(0);
}

//
// RREAT Memory API
//

addr_t rreat_alloc(rreat_t *rr, unsigned long size, unsigned long flags)
{
    static const unsigned long table[8] = {
        /* 0 */ 0,
        /* 1 */ PAGE_READONLY,
        /* 2 */ PAGE_READWRITE,
        /* 3 */ PAGE_READWRITE,
        /* 4 */ PAGE_EXECUTE,
        /* 5 */ PAGE_EXECUTE_READ,
        /* 6 */ PAGE_EXECUTE_READWRITE,
        /* 7 */ PAGE_EXECUTE_READWRITE,
    };
    
    assert(flags != 0 && flags < sizeofarray(table));
    
    addr_t ret = (addr_t) VirtualAllocEx(rr->handle, NULL, roundup2(size),
            MEM_COMMIT | MEM_RESERVE, table[flags]);
    assert(ret);
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

// create a new process object
rreat_t *rreat_process_init(const char *filename)
{
    STARTUPINFO si = {}; PROCESS_INFORMATION pi = {};
    assert(CreateProcess(filename, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
        NULL, NULL, &si, &pi));
    rreat_t *p = (rreat_t *) calloc(1, sizeof(rreat_t));
    assert(p);
    p->process_id = pi.dwProcessId;
    p->handle = pi.hProcess;
    rreat_thread_init(p, pi.hThread);
    return p;
}

// create a new thread object (returns thread id)
int rreat_thread_init(rreat_t *rr, HANDLE handle)
{
    int newsize = roundup2(rr->thread_count + 1);
    if(roundup2(rr->thread_count) != newsize) {
        rr->threads = (rreat_thread_t *) realloc(rr->threads, newsize);
        assert(rr->threads);
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
    assert(mem);
    rreat_read(rr, (addr_t) mi.lpBaseOfDll, mem, mi.SizeOfImage);
    // for now let's hope our binary doesn't destroy the PE headers
    IMAGE_DOS_HEADER *pImageDosHeader = (IMAGE_DOS_HEADER *) mem;
    if(pImageDosHeader->e_lfanew >= 0 && pImageDosHeader->e_lfanew <
            mi.SizeOfImage) {
        IMAGE_NT_HEADERS *pImageNtHeaders = (IMAGE_NT_HEADERS *)(
            (unsigned char *) mem + pImageDosHeader->e_lfanew);
        // needs more checking.
        IMAGE_SECTION_HEADER *pImageSectionHeader = (IMAGE_SECTION_HEADER *)(
            (unsigned char *) &pImageNtHeaders->OptionalHeader +
            pImageNtHeaders->FileHeader.SizeOfOptionalHeader);
        for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections;
                i++, pImageSectionHeader++) {
            // IDA will think the binary is still in raw-offset mode
            // so we have to set the raw offset & raw size to the virtual
            // address equivalents
            pImageSectionHeader->PointerToRawData =
                pImageSectionHeader->VirtualAddress;
            pImageSectionHeader->SizeOfRawData =
                pImageSectionHeader->Misc.VirtualSize;
        }
    }
    FILE *fp = fopen(filename, "wb");
    assert(fp);
    fwrite(mem, 1, mi.SizeOfImage, fp);
    fclose(fp);
    assert(VirtualFree(mem, 0, MEM_RELEASE));
}

// attach JIT Debugger to Process
void rreat_jitdbg_attach(rreat_t *rr)
{
    char path[MAX_PATH];
    _snprintf(path, sizeofarray(path), RREAT_JITDEBUGGER, rr->process_id);
    STARTUPINFO si = {}; PROCESS_INFORMATION pi = {};
    CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
}

// create a dummy thread
int rreat_thread_dummy(rreat_t *rr)
{
    addr_t addr = rreat_alloc(rr, 2, RREAT_RWX);
    HANDLE handle = CreateRemoteThread(rr->handle, NULL, 0,
        (LPTHREAD_START_ROUTINE) addr, NULL, 0, NULL);
    assert(handle != INVALID_HANDLE_VALUE);
    rreat_thread_init(rr, handle);
    return rr->thread_count - 1;
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
    CONTEXT ctx; unsigned long start = GetTickCount();
    while (start + milliseconds > GetTickCount()) {
        rreat_thread_suspend(rr, thread_id);
        rreat_context_get(rr, thread_id, &ctx, CONTEXT_FULL);
        if(ctx.Eip == addr) return RREAT_SUCCESS;
        rreat_thread_resume(rr, thread_id);
        Sleep(1);
    }
    return RREAT_WAIT;
}

//
// RREAT Simulate API
//

// init new object
rreat_simulate_t *rreat_simulate_init(rreat_t *rr)
{
    rreat_simulate_t *ret = (rreat_simulate_t *)
        calloc(1, sizeof(rreat_simulate_t));
    assert(ret);
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
    CONTEXT ctx;
    rreat_context_get(sim->_rr, thread_id, &ctx, CONTEXT_FULL);
    ctx.Eip += 2;
    rreat_context_set(sim->_rr, thread_id, &ctx);

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
    CONTEXT ctx;
    rreat_context_get(sim->_rr, thread_id, &ctx, CONTEXT_FULL);
    ctx.Eip = sim->end;
    rreat_context_set(sim->_rr, thread_id, &ctx);
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
        /* 0 */ -1, // invalid
        /* 1 */ 3,  // read
        /* 2 */ 1,  // write
        /* 3 */ 3,  // read or write
        /* 4 */ 0,  // exec
    };
    static const unsigned char table_size[9] = {
        /* 0 */ -1, // invalid
        /* 1 */ 0,  // 1 byte
        /* 2 */ 1,  // 2 bytes
        /* 3 */ -1, // invalid
        /* 4 */ 3,  // 4 bytes
        /* 5 */ -1, // invalid
        /* 6 */ -1, // invalid
        /* 7 */ -1, // invalid
        /* 8 */ 2,  // 8 bytes
    };
    assert(hwbp_index >= 0 && hwbp_index < 4);
    assert(flags > 0 && flags < sizeofarray(table_flags));
    assert(size > 0 && size < sizeofarray(table_size) &&
            table_size[size] != -1);

    rreat_hwbp_t *hwbp = (rreat_hwbp_t *) calloc(1, sizeof(rreat_hwbp_t));

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
    *(addr_t *) &install[1] = (addr_t) GetProcAddress(hKernel32,
            "AddVectoredExceptionHandler");

    // store address of the exception handler
    *(addr_t *) &install[6] = addr;

    // store the address of RemoveVectoredExceptionHandler
    *(addr_t *) &remove[1] = (addr_t) GetProcAddress(hKernel32,
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

