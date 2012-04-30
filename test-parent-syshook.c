#include <stdio.h>
#include <windows.h>
#include "rreat.h"

void hook_ZwCreateFile(rreat_t *rr, rreat_syshook_t *syshook, int thread_id)
{

}

void hook_ZwClose(rreat_t *rr, rreat_syshook_t *syshook, int thread_id)
{
}

int main(int argc, char *argv[])
{
    if(argc != 2) {
        printf("Usage: %s child.exe\n", argv[0]);
        return 0;
    }

    rreat_init();
    rreat_t *rr = rreat_process_init(argv[1]);

    // wait for oep
    rreat_process_wait_for_address_insert_while1(rr, 0, 0x401130, 1000);

    rreat_syshook_t *syshook = rreat_syshook_init(rr);

    rreat_syshook_set_hook(syshook, "ZwCreateFile", &hook_ZwCreateFile);
    rreat_syshook_set_hook(syshook, "ZwClose", &hook_ZwClose);

    //Sleep(10000);

    //rreat_jitdbg_attach(rr);
    Sleep(1000);

    rreat_thread_resume(rr, 0);

    WaitForSingleObject(rr->threads[0].handle, INFINITE);
    //Sleep(INFINITE);
    //rreat_process_terminate(rr, 0);
}
