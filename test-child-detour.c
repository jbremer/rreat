#include <stdio.h>
#include <windows.h>

int main()
{
    printf("Current Process: 0x%08x\n", GetCurrentProcess());

    MessageBox(NULL, "Body", "Title", 0);
}
