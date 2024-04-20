#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *BIN_SH = "/bin/sh\x00";

void setup_IO()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void shell(char **cmd)
{
    if (!strcmp(*cmd, BIN_SH))
    {
        system(*cmd);
    }
    else
    {
        puts("Try calling system(\"/bin/sh\").");
    }
}

int main()
{
    char input[64];

    setup_IO();

    puts(" _______  _     _  __    _  _______  __   __  _______  _______  ______   ");
    puts("|       || | _ | ||  |  | ||       ||  | |  ||       ||       ||    _ |  ");
    puts("|    _  || || || ||   |_| ||_     _||  | |  ||_     _||   _   ||   | ||  ");
    puts("|   |_| ||       ||       |  |   |  |  |_|  |  |   |  |  | |  ||   |_||_ ");
    puts("|    ___||       ||  _    |  |   |  |       |  |   |  |  |_|  ||    __  |");
    puts("|   |    |   _   || | |   |  |   |  |       |  |   |  |       ||   |  | |");
    puts("|___|    |__| |__||_|  |__|  |___|  |_______|  |___|  |_______||___|  |_|");
    puts("");
    puts("=========================================================================");
    puts("                         Stage 3: Free Shell");
    puts("=========================================================================");
    printf("Input => ");

    scanf("%s", input);

    return 0;
}
