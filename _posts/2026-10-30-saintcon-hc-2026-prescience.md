---
# Copy this file to _posts/YYYY-MM-DD-event-challenge.md (e.g. 2026-11-03-saintcon-2026-prescience.md)
# and put this post's images in assets/img/posts/event-challenge/ (same name, no date).
# Folders starting with "_" like _templates/ are not published, so this file never shows on the site.
title: "Prescience Writeup"
date: 2026-10-30 12:00:00 -0700 # must not be in the future, or the post is hidden
categories: [CTF, Saintcon2026] # max 2 levels
tags: [pwn] # lowercase, e.g. pwn, rev, crypto, forensics, jwt
description: A ret2libc pwn challenge.
# image: /assets/img/posts/event-challenge/banner.png # optional preview/banner image
---

# Prescience CTF Challenge

## Starting Off

We are given our binary, `ret2libc`, and the libc binary from the system, `libc.so.6`. The name of the files should be a good hint of where to start lol, but when we run `file ret2libc` we see:
```
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5a41d8630b66d20328d6d367298dc01079b8ad02, for GNU/Linux 3.2.0, not stripped
```

This is also good, as we see that it's not stripped, and it's the classic ELF I'm familiar with. The next thing I did after that was open up Ghidra to take a look at the disassembly for our `ret2libc` binary.

In Ghidra, we can see the labeled functions `main`, `pop_rdi_ret`, and `vulnerable`. Taking a quick look at the decompilation of `main`, we can see that it basically just calls `vulnerable` and then says bye bye. Surprise surprise, our vulnerable function is called `vulnerable`. 

Looking at that decompilation, we see it says "Say something: " and then calls `gets(input)` where input is a 64 byte char. `gets` doesn't cap the size of our input, so it's the classic overflow vulnerability. 

Next, we look at the stack and see what we have to work with. Well, basically nothing when we first look at it... but WAIT! There's more! Because `input` is the only variable in this function, we can actually overwrite `rip` to return to wherever we want. Sweet, we just need to overwrite that 64 byte char + 8 bytes for `rbp`, and we're at `rip`.

So where do we return? I assumed our `pop_rdi_ret` would be important, and if we look it literally only does 
```
POP RDI
RET
```
Long story short, we need a shell because there doesn't seem to be anywhere that might give us the flag on the binary. In order to do that, we are going to need to use that `libc.so.6` that the author kindly gave us. 

Originally, I tried writing the exploit to just go to the address of `system()` that Ghidra told me when I analyzed the libc binary, but turns out it isn't that simple. In a perfect world, I could just manually set `rip` to that address and set `rdi` to raw bytes of "/bin/sh" and call it a day. After much troubleshooting, turns out you actually need to find the address of libc's `system()`. Our end goal is `system(/bin/sh)`, so I guess it's kind of important that we have the right address...

## GOT Leak via ret2plt 

One thing that's important to note (I should've realized this before, but I've never done a ret2libc) is that it's on the system, and so ASLR will be enabled here. That means we need a way to get the base address of `libc.so.6` on the remote system every time we run our solve script so that we can actually access what we want. Sadly, we can't just guess.

We can use pwntools (the GOAT) to call `puts` and use the address of `puts` as the argument, that way it'll leak that address! That's our first payload. After we get the address of `puts` from the GOT, we save that address and do `memleak - libc.sym.puts` to get the base address of `libc`. Now that we have that, pwntools can reference that to get the offset of `system()` from the binary we've been given.

## ret2libc time

Now we have our second payload! Since our other one looped back to `main()`, we can just do another overflow to keep our super fun ROP thing going on. This one sets the argument for `system()` to be `b'/bin/sh'` from the `libc` from remote. I tried this once, then it segfaulted. Not good, the stack was misaligned. To fix that, I added a return to the `RET` instruction from our `pop_rdi_ret` gadget to align the stack to 16 bytes.

Finally, we set our last `rip` overwrite to `libc.sym.system`, and we finally get our `system('/bin/sh')` call! Now we should have a shell and can just rip the flag off of the server.

## Solve Script

``` python
from pwn import *

binary = "./ret2libc"
elf = context.binary = ELF(binary, checksec=False)
libc = ELF('libc.so.6', checksec=False)
gs = """
break main
continue
"""

if args.REMOTE:
    p = remote("prescience.youcanhack.me", 1303)
elif args.GDB:
    p = gdb.debug(binary, gdbscript=gs)
else:
    p = elf.process()

POP_RDI = 0x00401166
padding = 0x48
payload = flat(b'A' * padding, POP_RDI, elf.got['puts'], elf.plt['puts'], elf.symbols['main'])

p.recvuntil("Say something: ")
p.sendline(payload)
p.recvline()
memleak = u64(p.recv(6) + b'\x00\x00')
libc.address = memleak - libc.sym.puts

p.recvuntil("Say something: ")
payload2 = flat(b'A' * padding, POP_RDI, next(libc.search(b'/bin/sh')), POP_RDI+1, libc.sym.system)

p.sendline(payload2)
p.interactive()
```