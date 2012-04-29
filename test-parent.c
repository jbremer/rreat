#include <stdio.h>
#include <windows.h>
#include "rreat.h"

int main(int argc, char *argv[])
{
    if(argc != 2) {
        fprintf(stderr, "Usage: %s child.exe\n", argv[0]);
        return 0;
    }

    rreat_t *rr = rreat_process_init(argv[1]);

    // wait until the process has initialized (0x401130 = magic value for the
    // entry point)
    rreat_process_wait_for_address_insert_while1(rr, 0, 0x401130, 1000);

    // mov eax, 0xdeadb00b ; retn
    unsigned char hook1[] = {0xb8, 0x0b, 0xb0, 0xad, 0xde, 0xc3};
    addr_t addr1 = rreat_alloc(rr, sizeof(hook1), RREAT_RWX);
    rreat_write(rr, addr1, hook1, sizeof(hook1));

    addr_t addr_GetCurrentProcess = (addr_t) GetProcAddress(
        GetModuleHandle("kernel32.dll"), "GetCurrentProcess");

    // do a normal jmp detour for GetCurrentProcess()
    rreat_detour_t *detour1 = rreat_detour_address(rr, addr_GetCurrentProcess,
        addr1, RREAT_DETOUR_JMP);

    addr_t addr_MessageBoxA = (addr_t) GetProcAddress(
        LoadLibrary("user32.dll"), "MessageBoxA");

    // push ebp ; mov ebp, esp ; push 0 ; push dword [ebp+0x14] ;
    // push dword [ebp+0x10] ; push 0 ; jmp MessageBoxA+16
    unsigned char hook2[] = {0x55, 0x8b, 0xec, 0x6a, 0x00, 0xff, 0x75, 0x14,
        0xff, 0x75, 0x10, 0x6a, 0x00, 0xe9, 0x00, 0x00, 0x00, 0x00};

    addr_t addr2 = rreat_alloc(rr, sizeof(hook2), RREAT_RWX);
    // the relative jump at the end of the hook points to MessageBoxA+16
    *(addr_t *) &hook2[sizeof(hook2) - 4] = (addr_MessageBoxA + 16) - (addr2 +
        sizeof(hook2) - 5) - 5;
    rreat_write(rr, addr2, hook2, sizeof(hook2));

    // do a fpu detour for MessageBoxA()
    rreat_detour_t *detour2 = rreat_detour_address(rr, addr_MessageBoxA,
        addr2, RREAT_DETOUR_FPU);

    rreat_thread_resume(rr, 0);

    Sleep(500);
    rreat_process_terminate(rr, 0);
}
