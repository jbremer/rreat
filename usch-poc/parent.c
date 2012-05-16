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
#include <stdio.h>
#include <windows.h>
#include "../rreat.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// declaration of important structures for the ZwCreateFile() function

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/*

Original Declaration of ZwCreateFile(). In our hook we have access to the
arguments by using the `args' variabele, e.g. args[0] is FileHandle and
args[2] is ObjectAttributes.

NTSTATUS ZwCreateFile(
  __out     PHANDLE FileHandle,
  __in      ACCESS_MASK DesiredAccess,
  __in      POBJECT_ATTRIBUTES ObjectAttributes,
  __out     PIO_STATUS_BLOCK IoStatusBlock,
  __in_opt  PLARGE_INTEGER AllocationSize,
  __in      ULONG FileAttributes,
  __in      ULONG ShareAccess,
  __in      ULONG CreateDisposition,
  __in      ULONG CreateOptions,
  __in_opt  PVOID EaBuffer,
  __in      ULONG EaLength
);

*/

void hook_ZwCreateFile(rreat_syshook_t *syshook, unsigned long *args,
    int thread_id, int pre_event)
{
    if(pre_event) {
        OBJECT_ATTRIBUTES ObjectAttributes;

        // second argument is ObjectAttributes
        rreat_read(syshook->_rr, args[2], &ObjectAttributes,
            sizeof(OBJECT_ATTRIBUTES));

        UNICODE_STRING ObjectName;

        // read the unicode string object
        rreat_read(syshook->_rr, (addr_t) ObjectAttributes.ObjectName,
            &ObjectName, sizeof(UNICODE_STRING));

        wchar_t wszFileName[256] = {0}; int len = 0;

        // read the unicode filename, or atleast a part of it.
        len = MIN(ObjectName.Length, sizeof(wszFileName));
        rreat_read(syshook->_rr, (addr_t) ObjectName.Buffer, wszFileName, len);
        wszFileName[len >> 1] = 0;

        fprintf(stderr, "Opening File: \"%S\" :)\n", wszFileName);
    }
    else {
        CONTEXT ctx; rreat_context_get(syshook->_rr, thread_id, &ctx,
            CONTEXT_FULL);
        fprintf(stderr, "Return Value: 0x%08x %d\n", ctx.Eax, ctx.Eax);
    }
}

int main(int argc, char *argv[])
{
    fprintf(stderr, "Universal System Call Hooking PoC   "
        "(C) 2012 Jurriaan Bremer\n");

    rreat_init();

    rreat_t *rr = rreat_process_init("child.exe", NULL);

    // wait until the child hits the OEP (Original Entry Point), this address
    // is hardcoded here, this is not good at all (for various reasons), but
    // suffices for this test (if you recompile the binary yourself, you might
    // have change this address, use PEiD or a similar tool to obtain the OEP)
    // note that we wait for the process to reach OEP so we can be sure that
    // that the process has finished initializing.
    rreat_process_wait_for_address_insert_while1(rr, 0, 0x401130, 1000);

    // we initialize a syshook (which is short for system call hook) object
    rreat_syshook_t *syshook = rreat_syshook_init(rr);

    // we place a hook at an API of choice.
    rreat_syshook_set_hook(syshook, "ZwCreateFile", &hook_ZwCreateFile);

    // resume the childs main thread, with a hook for ZwCreateFile()
    rreat_thread_resume(rr, 0);

    // wait until the childs main thread exits
    WaitForSingleObject(rr->threads[0].handle, INFINITE);

    // im terribly sorry for not cleaning up my mess.
}
