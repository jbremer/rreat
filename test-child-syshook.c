#include <stdio.h>
#include <windows.h>

int main()
{
    FILE *fp = fopen("aup", "w");
    fclose(fp);
}
