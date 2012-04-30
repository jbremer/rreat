#include <stdio.h>
#include <windows.h>

int main()
{
    HANDLE hFile = CreateFile("aup", GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    printf("handle: %p\n", hFile);
    CloseHandle(hFile);

    //Sleep(10000);
}
