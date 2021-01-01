#pragma GCC optimize("O0")
#include <stdio.h>
#include <unistd.h>

int
main()
{
    fprintf(stderr, "Welcome to echo, live edition!\n");
    fprintf(stderr, "Enter something and this program will repeat it.\n");
    char something_secret[64];
    FILE *f = fopen("flag", "r");
    if (f == NULL)
      {
        fprintf(stderr, "Failed to open flag file.\n");
        return 1;
      }
    fgets(something_secret, 64, f);
    char data[64] = {0};
    read(0, data, 63);
    fprintf(stderr, data);
    return 0;
}
