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

int main()
{
    char authorization[13] = "UNAUTHORIZED";
    char username[64];

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
    puts("                         Stage 2: Authorization");
    puts("=========================================================================");
    printf("Username => ");

    scanf("%s", username);

    printf("Greetings, %s. Your are %s.\n", username, authorization);

    if (!strcmp(authorization, "AUTHORIZED"))
    {
        puts("[ ACCESS GRANTED ]");
        shell();
    }
    else
    {
        puts("Intruder alert!");
    }

    return 0;
}
