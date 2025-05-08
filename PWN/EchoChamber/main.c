#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup_IO()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void shell()
{
    system("/bin/sh");
}

void main()
{
    char input[256];

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
    puts("                         Stage 4: Echo Chamber");
    puts("=========================================================================");
    printf("Enter Input => ");

    fgets(input, 255, stdin);

    puts("ECHO:");
    printf(input);

    exit(0);
}
