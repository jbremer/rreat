#include <stdio.h>
#include <windows.h>
#include "rreat.h"

#define assert(expr) if((expr) == 0) EXITERR("%s", #expr)
// #define assert(expr) expr

#define EXITERR(msg, ...) _rreat_exit_error(__FUNCTION__, __LINE__, \
        msg, ##__VA_ARGS__)
 
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

// create a new process object
rreat_t *rreat_process_init(const char *filename)
{
	STARTUPINFO si = {}; PROCESS_INFORMATION pi = {};
	assert(CreateProcess(filename, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
		NULL, NULL, &si, &pi));
	rreat_t *p = (rreat_t *) calloc(1, sizeof(rreat_t));
	assert(p);
	p->handle = pi.hProcess;
	rreat_thread_init(p, pi.hThread);
	return p;
}

// create a new thread object
rreat_thread_t *rreat_thread_init(rreat_t *rr, HANDLE handle)
{
	int newsize = roundup2(rr->thread_count + 1);
	if(roundup2(rr->thread_count) != newsize) {
		rr->threads = (rreat_thread_t *) realloc(rr->threads, newsize);
		assert(rr->threads);
	}
	rreat_thread_t *t = &rr->threads[rr->thread_count];
	t->thread_id = rr->thread_count++;
	t->handle = handle;
	return t;
}

// dump a series of pages
void rreat_dump_module(rreat_t *rr, addr_t base_addr, const char *filename)
{
	MEMORY_BASIC_INFORMATION mbi;
	assert(VirtualQueryEx(rr->handle, (void *) base_addr, &mbi,
		sizeof(mbi)) == sizeof(mbi));
	// we don't need the size from what's before AllocationBase
	int size = (addr_t) mbi.BaseAddress - (addr_t) mbi.AllocationBase +
		mbi.RegionSize;
	void *mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	assert(mem);
	rreat_read(rr, (addr_t) mbi.AllocationBase, mem, size);
	FILE *fp = fopen(filename, "wb");
	assert(fp);
	fwrite(mem, 1, size, fp);
	fclose(fp);
	assert(VirtualFree(mem, 0, MEM_RELEASE));
}

//
// RREAT Simulate API
//

// init new object
rreat_simulate_t *rreat_simulate_init(rreat_t *rr)
{
    rreat_simulate_t *ret = (rreat_simulate_t *) \
            calloc(1, sizeof(rreat_simulate_t));
    assert(ret);
    ret->_rr = rr;
    return ret;
}

// assign address, size and offset (size is the size to copy, offset is the
// offset where the code will jmp after finishing)
void rreat_simulate_address(rreat_simulate_t *rr, addr_t addr, int size,
        int offset)
{
    assert(size >= 5);
    rr->addr = addr;
    rr->size = max(size, offset);
    rr->offset = offset;
}

// apply in the process
void rreat_simulate_apply(rreat_simulate_t *sim)
{
    sim->_mem = rreat_alloc(sim->_rr, sim->size + 2, RREAT_RWX);
    sim->_backup = malloc(sim->size);
    // read original code
    rreat_read(sim->_rr, sim->addr, sim->_backup, sim->size);
    // write new code with while(1) loop
    rreat_write(sim->_rr, sim->_mem, sim->_backup, sim->size);
    rreat_write(sim->_rr, sim->_mem + sim->size, "\xeb\xfe", 2);
    // write detour jmp
    unsigned char jmp[5] = {0xe9};
    *(addr_t *) &jmp[1] = sim->_mem - sim->addr - 5;
    rreat_write(sim->_rr, sim->addr, jmp, sizeof(jmp));
}

// wait for a certain thread to finish this `simulation'
int rreat_simulate_wait(rreat_simulate_t *sim, rreat_thread_t *t,
        int milliseconds)
{
    unsigned long start = GetTickCount();
    while (start + milliseconds > GetTickCount()) {
        assert(SuspendThread(t->handle) != -1);
        CONTEXT ctx = {CONTEXT_FULL};
        assert(GetThreadContext(t->handle, &ctx));
        if(ctx.Eip == sim->_mem + sim->offset) {
            return RREAT_SUCCESS;
        }
        assert(ResumeThread(t->handle) != -1);
        Sleep(1);
    }
    return RREAT_WAIT;
}

// restore the thread to the real address
void rreat_simulate_restore(rreat_simulate_t *sim, rreat_thread_t *t)
{
    assert(SuspendThread(t->handle) != -1);
    CONTEXT ctx = {CONTEXT_FULL};
    assert(GetThreadContext(t->handle, &ctx));
    ctx.Eip = sim->addr + sim->offset;
    assert(SetThreadContext(t->handle, &ctx));
    assert(ResumeThread(t->handle) != -1);
}

// free simulate api
void rreat_simulate_free(rreat_simulate_t *sim)
{
    // restore the original code
    rreat_write(sim->_rr, sim->addr, sim->_backup, sim->size);
    // free the rest
    rreat_free(sim->_rr, sim->_mem);
    free(sim->_backup);
    free(sim);
}