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
#ifndef __RREAT__
#define __RREAT__

#include "config.h"

typedef unsigned long addr_t;

struct _rreat;

typedef struct _rreat_simulate_t {
    addr_t start;
    addr_t end;

    // internal
    struct _rreat_t *_rr;
    addr_t _mem;
    void *_backup;
} rreat_simulate_t;

typedef struct _rreat_thread_t {
    int thread_id;
    HANDLE handle;
} rreat_thread_t;

typedef struct _rreat_t {
    int process_id;
    HANDLE handle;
    int thread_count;
    rreat_thread_t *threads;
} rreat_t;

typedef struct _rreat_veh_t {
    addr_t mem;
    LPTHREAD_START_ROUTINE remove_handler;
} rreat_veh_t;

typedef struct _rreat_hwbp_t {
    addr_t addr;
    int flags;
    int size;
} rreat_hwbp_t;

#define RREAT_DETOUR_BACKUP_MAXLENGTH 0x20

typedef struct _rreat_detour_t {
    addr_t addr;
    unsigned char backup[RREAT_DETOUR_BACKUP_MAXLENGTH];
    int length;
    addr_t _extra_data;
} rreat_detour_t;

#define RREAT_SUCCESS 0
#define RREAT_WAIT    1

#define RREAT_READ   1
#define RREAT_WRITE  2
#define RREAT_EXEC   4
#define RREAT_RW     (RREAT_READ | RREAT_WRITE)
#define RREAT_RWX    (RREAT_READ | RREAT_WRITE | RREAT_EXEC)

#define RREAT_DETOUR_JMP 0 // normal jmp `payload' detour, requires 5 bytes.
#define RREAT_DETOUR_FPU 1 // address is stored as floating point,

#ifndef sizeofarray
#define sizeofarray(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

//
// RREAT Initialize Function
//

void rreat_init();

//
// RREAT Memory API
//

// allocate memory in process
addr_t rreat_alloc(rreat_t *rr, unsigned long size, unsigned long flags);
// free memory in process
void rreat_free(rreat_t *rr, addr_t addr);
// write to memory in process
void rreat_write(rreat_t *rr, addr_t addr, const void *src, unsigned long size);
// read from memory in process
void rreat_read(rreat_t *rr, addr_t addr, void *dest, unsigned long size);

//
// RREAT Debugger API
//

// get the context of a thread
void rreat_context_get(rreat_t *rr, int thread_id, CONTEXT *ctx,
        unsigned long flags);

// set the context of a thread
void rreat_context_set(rreat_t *rr, int thread_id, CONTEXT *ctx);

// get the instruction pointer of a thread
addr_t rreat_ip_get(rreat_t *rr, int thread_id);

// set the instruction pointer of a thread
void rreat_ip_set(rreat_t *rr, int thread_id, addr_t addr);

// add delta to the instruction pointer of a thread
void rreat_ip_add(rreat_t *rr, int thread_id, int delta);

// create a new process object
rreat_t *rreat_process_init(const char *filename, char *cmdline);

// attach to a process
rreat_t *rreat_process_attach(unsigned long pid, unsigned long desired_access);

// open a handle to each thread, only useful after attaching to a process
void rreat_attach_all_threads(rreat_t *rr);

// terminate a process
void rreat_process_terminate(rreat_t *rr, unsigned int exit_code);

// create a new thread object (returns thread id)
int rreat_thread_init(rreat_t *rr, HANDLE handle);

// resume a thread
void rreat_thread_resume(rreat_t *rr, int thread_id);

// suspend a thread
void rreat_thread_suspend(rreat_t *rr, int thread_id);

// get a thread object by its id
rreat_thread_t *rreat_thread_by_id(rreat_t *rr, int thread_id);

// dump a series of pages
void rreat_dump_module(rreat_t *rr, addr_t base_addr, const char *filename);

// attach JIT Debugger to Process
void rreat_jitdbg_attach(rreat_t *rr);

// places the thread in a while(1) loop
// with a jmp behind it that will point to the original address
void rreat_thread_while1(rreat_t *rr, int thread_id);

// waits until the thread hits the given address
int rreat_thread_wait_for_address(rreat_t *rr, int thread_id, addr_t addr,
        int milliseconds);

// wait for the first thread to get to the entry point.
int rreat_process_wait_for_address_insert_while1(rreat_t *rr, int thread_id,
    addr_t addr, int milliseconds);

// get the address of a function
addr_t rreat_get_address(const char *library, const char *function);

//
// RREAT Simulate API
//

// init new object
rreat_simulate_t *rreat_simulate_init(rreat_t *rr);

// assign start and end address, `wait' will run until `end' is hit.
void rreat_simulate_address(rreat_simulate_t *rr, addr_t start, addr_t end);

// apply in the process
void rreat_simulate_apply(rreat_simulate_t *sim);

// wait for a certain thread to finish this `simulation'
int rreat_simulate_wait(rreat_simulate_t *sim, int thread_id, int milliseconds);

// restore the thread to the real address
void rreat_simulate_restore(rreat_simulate_t *sim, int thread_id);

// free simulate api object
void rreat_simulate_free(rreat_simulate_t *sim);

// single-threaded blocking `simulate' event.
void rreat_simulate_single(rreat_t *rr, addr_t start, addr_t end,
        int milliseconds, int thread_id);

//
// RREAT Debug Register API
//

rreat_hwbp_t *rreat_debugreg_trap(rreat_t *rr, int thread_id, int hwbp_index,
        addr_t addr, int flags, int size);
void rreat_debugreg_disable(rreat_t *rr, int thread_id, int hwbp_index);

//
// RREAT Vectored Exception Handler API
//

rreat_veh_t *rreat_veh_install(rreat_t *rr, addr_t addr, int first_handler);
void rreat_veh_uninstall(rreat_t *rr, rreat_veh_t *veh);

//
// RREAT Detour API
//

rreat_detour_t *rreat_detour_address(rreat_t *rr, addr_t addr, addr_t payload,
    int detour_type);
void rreat_detour_remove(rreat_t *rr, rreat_detour_t *detour);

//
// RREAT Generic Syscall Hooking
//

struct _rreat_syshook_t;

typedef void (*rreat_syshook_hook_t)(struct _rreat_syshook_t *syshook,
    unsigned long *args, int thread_id, int pre_event);

typedef void (*rreat_syshook_default_hook_t)(struct _rreat_syshook_t *syshook,
    unsigned long syscall_number, unsigned long *args, int thread_id,
    int pre_event);

typedef struct _rreat_syshook_t {
    rreat_t *_rr;
    // jump instruction with segment prefix (that makes seven bytes.)
    unsigned char far_jump_address[6];
    addr_t jump_address;
    // event that the child will signal upon receiving a new syscall
    HANDLE event_local, event_remote;
    // thread handle of notify thread
    HANDLE thread_handle;
    // 64k table containing each index, set the index if the parent
    // has to handle it
    addr_t table;
    // handler in the child which will handle each syscall
    addr_t handler;
    // if installed, will be called if no the syscall isnt defined in the
    // `callback' table.
    rreat_syshook_default_hook_t default_callback;
    // lookup table in the parent, which holds callbacks
    rreat_syshook_hook_t callback[64 * 1024];
} rreat_syshook_t;

rreat_syshook_t *rreat_syshook_init(rreat_t *rr);
unsigned short rreat_syshook_syscall_name_to_number(const char *name);
const char *rreat_syshook_syscall_number_to_name(unsigned short number);
void rreat_syshook_set_hook(rreat_syshook_t *syshook, const char *name,
    rreat_syshook_hook_t hook);
void rreat_syshook_unset_hook(rreat_syshook_t *syshook, const char *name);

#endif
