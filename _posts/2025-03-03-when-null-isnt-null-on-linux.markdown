---
layout:     post
title:      "When NULL isn't null: mapping memory at 0x0 on Linux"
date:       2025-03-03 18:00:00
tags:       linux, security, c, cpp, programming
---

When we think of a null pointer, `NULL` in C or `nullptr` in C++, we typically assume it is "invalid" or "not pointing to a valid memory location". But what if I tell you that a null pointer can actually point to valid memory under certain conditions? In this post, we will see this on Linux.

## An interview question

*Note: For the sake of discussion, let's assume that null pointer is represented as zero (or an address with a value of zero).*

When conducting technical interviews, I have been assessing candidates' depth of knowledge through a particular question:

> What happens when the following C or C++ code executes: `*(int*)(rand_int()) = 0x41424344;`
> 
> Assume that `rand_int` returns any valid integer.

I don't specify a CPU architecture, operating system, privilege level (user vs kernel space) or compiler version but if asked, I clarify that we are considering x86-64, user-space Linux, and either GCC or Clang.

From the point of C or C++ standards, this code results in an undefined behavior. However, I ask this question since I am interested in whether the candidate understands what actually happens at runtime.

## Possible outcomes

When executed, the code attempts to write a 4-byte value of 0x41424344 to a random memory address. Its outcome depends on two conditions:

* If the address is within the process' mapped virtual address space and has write permissions, the write operation will succeed.
* If the address is unmapped or lacks write permissions, the process will "crash".

Or at least this is what some candidates say. In practice, this is more nuanced. The invalid memory access is intercepted by the CPU, which triggers an exception. The Linux kernel then handles this by sending a `SIGSEGV` (Segmentation Fault) signal to the process. At this point if the process has a registered signal handler for `SIGSEGV`, that handler is executed. Otherwise, the process is terminated.

**EDIT:** Actually, there is yet another case. If the address happens to be before the main thread stack, the kernel will expand the stack and then the first case apply. (Thanks to MrQubo from justCatTheFish for pointing this out!) This can be seen on the screenshot from the [Pwndbg](https://github.com/pwndbg/pwndbg) plugin for GDB below. We first show the stack memory mapping, then patch the next instruction executed by the program to write value to memory at address defined by register RAX, then we set RAX register to address before main thread stack and we execute a single instruction. Finally, we can see that the stack got expanded.

![Screenshot of stack expanded by the kernel]({{ site.url }}assets/posts/vmmap-expand-stack.png)

*Fun fact: the JVM (Java Virtual Machine) uses this exact mechanism to detect invalid memory accesses and to throw its `NullPointerException` errors.*

## What if rand\_int returns 0?

A natural follow-up question I ask: *What happens if `rand_int` returns 0? Can address 0x0 be mapped?*

Suprisingly, the answer is **yes**, under certain conditions.

On Linux, memory allocations are handled by the `mmap` system call which is internally used by the `malloc` or `new` C or C++ functions. With `mmap` it is possible to explicitly request the memory to be allocated at address 0x0, but whether the system grants this request depends on it configuration.

This configuration is the `vm.mmap_min_addr` sysctl parameter which determines the minimum possible address at which `mmap` can allocate memory. It can be read either with the `sysctl` command or by reading a corresponding file in the procfs filesystem, as follows:

```bash
$ sysctl vm.mmap_min_addr
vm.mmap_min_addr = 65536

$ cat /proc/sys/vm/mmap_min_addr
65536
```

Of course we can modify this setting if we were a root user (with the `sudo sysctl -w vm.mmap_min_addr=0` command).

## Why using the value of 65536?

I got asked by some folks from Hackerspace Cracow why isn't the value just 1? This is because we don't only care about strict null pointer dereferences. For example, if we have code like this in C that calls a function pointer that is pointed by the `func` field of some structure - `ptr->func()` and `ptr` is `0` - then the code will actually dereference memory at address `0 + offsetof(SomeStruct, func)` and take the address to jump to from there. And this offset may be even bigger than e.g. 1024 since there are some big structures in the kernel code.

In other words, we don't want to protect just the address zero. We want to protect all potential small addresses that a kernel code bug could hit.

## But why is there such config?

I believe the reason for introducing this sysctl parameter was mitigating security vulnerabilities such as null pointer dereferences in Linux kernel code which could be exploited by unprivileged user space programs to escalate privileges and become root. In other words, an attacker could allocate memory on address 0x0 in a user-space program and then trigger a Linux kernel null pointer dereference to access this memory from the kernel. Then they used this to hijack the control flow of the kernel and become root.

Nowadays, this is rather a relic of the past due to [SMAP](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention) and [SMEP](https://en.wikipedia.org/wiki/Control_register#SMEP) mitigations on x86-64 and [PAN](https://en.wikipedia.org/wiki/AArch64#:~:text=A%20new%20Privileged%20Access%20Never%20(PAN)%20state%20bit%20provides%20control%20that%20prevents%20privileged%20access%20to%20user%20data%20unless%20explicitly%20enabled.) on Arm64 architectures (though, [PAN was or is broken?](https://blog.siguza.net/PAN/)) as those mitigations prevent the kernel from accessing (SMAP) or excecuting (SMEP) user-space addresses (such as 0x0 address).

It is also worth to mention that all standard Linux distributions set `vm.mmap_min_addr` to 0x10000 (previously 0x1000) or some other value, but also, processes run as root bypass the `vm.mmap_min_addr` configuration (and can allocate at address 0x0). This also means that the null pointer dereferences can be exploited in suid binaries, however, one would need to find a way to allocate at address 0x0 first...

*Fun fact: Actually, there is a reason to set `vm.mmap_min_addr = 0` which is to... use the `vm86` system call which allows one to emulate virtual-8086 CPU mode. This requirement can be seen in the [Linux kernel v6.13.5 code: source/arch/x86/kernel/vm86_32.c#L208-L232](https://elixir.bootlin.com/linux/v6.13.5/source/arch/x86/kernel/vm86_32.c#L208-L232)*

## Example of allocating memory at 0x0

For completeness, here is a minimal example program that will allocate memory on address 0x0 which would be valid:

```c
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    size_t size = getpagesize();  // Allocate one page

    // Allocate 1 page of memory (usually: 0x1000 bytes) at address 0x0
    void *mapped = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("Memory successfully mapped at %p (size: %lx)\n", mapped, size);

    *(int*)mapped = 0x41424344;
    printf("Value written to and read from address %p: 0x%x\n", mapped, *(int*)mapped);

    // Clean up
    munmap(mapped, size);
    return 0;
}
```

It can be tested by setting the `vm.mmap_min_addr=0`:

```bash
$ sudo sysctl vm.mmap_min_addr=0
vm.mmap_min_addr = 0

$ ./a.out
Memory successfully mapped at (nil) (size: 1000)
Value written to and read from address (nil): 0x41424344
```

## Final thoughts

While null pointers are generally assumed to be invalid, their actual behavior depends on the system's memory management rules. 
The `vm.mmap_min_addr` sysctl parameter is one such rule that allows us to prevent mapping memory at 0x0. 
However, if modified, a null pointer could indeed point to a valid, accessible memory location.

So next time someone says a null pointer is always invalid -- well, you know better!

### Like this post?

If you like this post, please share my posts on [X/Twitter](https://x.com/disconnect3d_pl/status/1896662642267488621), [InfoSec.exchange](https://infosec.exchange/@disconnect3d/114100443532352547) or [LinkedIn](https://www.linkedin.com/posts/dominik-czarnota_i-wrote-a-blog-post-about-null-pointers-activity-7302433908619382786-OoCn) posts! Also, if Linux or C/C++ security mitigations are of your interest, you may also want to read other content I wrote:
* On [`_FORTIFY_SOURCE` typos bugs](https://blog.trailofbits.com/2023/04/20/typos-that-omit-security-features-and-how-to-test-for-them/)
* On [cstrnfinder tool I wrote to find stupid C bugs](http://github.com/disconnect3d/cstrnfinder)
* On [a KASLR bypass in privilege-less containers I reported to Linux kernel back then](https://blog.trailofbits.com/2024/03/08/out-of-the-kernel-into-the-tokens/#:~:text=of%20expected%20algorithms.-,KASLR%20bypass%20in%20privilege%2Dless%20containers,-Next%20is%20a)
* On [Understanding AddressSanitizer: Better memory safety for your code](https://blog.trailofbits.com/2024/05/16/understanding-addresssanitizer-better-memory-safety-for-your-code/)
* On [Sanitizing your C++ containers: ASan annotations step-by-step](https://blog.trailofbits.com/2024/09/10/sanitize-your-c-containers-asan-annotations-step-by-step/)
* On [Understanding Docker escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) (though that's about Linux kernel features that build containers rather than C or C++ code)


EDIT 2025.03.04: Added two things to the blog post - information about stack expansion and the "Why using the value of 65536?" paragraph. Thanks to MrQubo for info on the first one and folks from Hackerspace Kraków for some interesting questions.
