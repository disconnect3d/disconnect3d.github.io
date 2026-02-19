---
layout: page
title: About me
permalink: /about/
---

This blog contains my private/personal notes on random topics I found worth to write about.

Here is also a bunch of info on me ;).

* Name: Dominik 'disconnect3d' Czarnota
 
* E-mail: [dominik.b.czarnota+dc@gmail.com](mailto:dominik.b.czarnota+dc@gmail.com)

* GitHub: [disconnect3d](https://github.com/disconnect3d)
 
* Twitter/X: [@disconnect3d_pl](https://twitter.com/disconnect3d_pl) (prefer e-mail)

* Infosec.exchange: [@disconnect3d](https://infosec.exchange/@disconnect3d)
 
* LinkedIn: [Dominik Czarnota](https://www.linkedin.com/in/dominik-czarnota-55b2a78a/)

* Staff Security Engineer @ [Trail of Bits](https://www.trailofbits.com/)

* Captain of [justCatTheFish](https://ctftime.org/team/33893) CTF team (previously captain of [Just Hit the Core](https://ctftime.org/team/13830))

* Maintainer of [Pwndbg -- a plugin for GDB and LLDB for low level debugging, security research, reverse engineering and exploit development](https://github.com/pwndbg/pwndbg)

* I am a reviewer of [Paged Out!](https://pagedout.institute/) free magazine about programming, security, hacking, computers, electronics, demoscene and other similar topics.

* Education: Applied Computer Science at AGH University of Science and Technology in Cracow, Poland

  * Master thesis (in Polish): [Reverse engineering, finding and exploiting bugs in native apps on x86 and x86-64]({{ site.url }}assets/about_me/disconnect3d_master_thesis.pdf). The reviews are inside.

  * Bachelor thesis (in Polish): [Impact of memory layout organization of complicated data structures on binary code efficiency]({{ site.url }}assets/about_me/disconnected_bachelor_thesis.pdf). Reviews: [supervisor’s]({{ site.url }}assets/about_me/bachelor_thesis_review1.pdf), [reviewer’s]({{ site.url }}assets/about_me/bachelor_thesis_review2.pdf).

  * (Past) Member and a president (for 2 years) of [KNI Kernel](http://kernel.fis.agh.edu.pl/)

### Some publications

**Blog posts written for Trail of Bits blog:**
* [[2025.12.16] Use GWP-ASan to detect exploits in production environments](https://blog.trailofbits.com/2025/12/16/use-gwp-asan-to-detect-exploits-in-production-environments/) - co-authored with Dominik Klemba
* [[2024.09.10] Sanitize your C++ containers: ASan annotations step-by-step](https://blog.trailofbits.com/2024/09/10/sanitize-your-c-containers-asan-annotations-step-by-step/) - co-authored with Dominik Klemba
* [[2024.05.16] Understanding AddressSanitizer: Better memory safety for your code](https://blog.trailofbits.com/2024/05/16/understanding-addresssanitizer-better-memory-safety-for-your-code/) - co-authored with Dominik Klemba
* [[2024.03.08] KASLR bypass in privilege-less containers](https://blog.trailofbits.com/2024/03/08/out-of-the-kernel-into-the-tokens/#:~:text=of%20expected%20algorithms.-,KASLR%20bypass%20in%20privilege%2Dless%20containers,-Next%20is%20a) - detailing a Linux  vulnerability which allowed for leaking kernel modules addresses and bypassing the kernel address space layout randomization (KASLR) mitigation
* [[2023.04.20] Typos that omit security features and how to test for them](https://blog.trailofbits.com/2023/04/20/typos-that-omit-security-features-and-how-to-test-for-them/) - about some `_FORTIFY_SOURCE` compiler mitigations typos
* [[2020.06.09] How to check if a mutex is locked in Go](https://blog.trailofbits.com/2020/06/09/how-to-check-if-a-mutex-is-locked-in-go/)
* [[2020] Cstrnfinder research](http://github.com/disconnect3d/cstrnfinder) - a research about finding stupid string related bugs in C/C++ codebases
* [[2019.07.19] Understanding Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/) - a post where I broke down a privileged Docker escape technique published by Felix Wilhelm (@_fel1x) on Twitter/X

**Articles for "Programista" polish programming magazine:**
 * [[2023] Debugowanie niskopoziomowe z Pwndbg](https://programistamag.pl/programista-42023-109-wrzesienpazdziernik-2023-debugowanie-niskopoziomowe-z-pwndbg/) - An article about [Pwndbg](https://github.com/pwndbg/pwndbg), a plugin for GDB for security research, reverse engineering and exploit development.
 * [[2021] Pułapki w języku Go]([https://szukaj.programistamag.pl/uuid/34796811fe73d50f4615a76ba993dba1c1ae383b](https://programistamag.pl/pulapki-w-jezyku-go/)) - Go programming language traps that may lead to security vulnerabilities.
 * [[2021] Przegląd błędów w CPythonie]([https://szukaj.programistamag.pl/uuid/8202ea027c6b7810f4b62ec56f088cb478a53e9f](https://programistamag.pl/programista-4-2021-98/#:~:text=Przegl%C4%85d%20b%C5%82%C4%99d%C3%B3w%20w%20CPythonie)) - A review of known CPython bugs that were reported before in the official Python bugtracker - bugs.python.org.
 * [[2021] Pwn2Win CTF 2021 - atak Spectre](https://programistamag.pl/programista-3-2021-97/#:~:text=Pwn2Win%20CTF%202021%20%E2%80%93%20atak%20Spectre) - write-up of a CTF challenge where we had to exploit Spectre vulnerability. Written with [Arusekk](https://github.com/Arusekk).
 * [[2018] Teaser Dragon CTF 2018 - zadania production oraz cryptovm](https://programistamag.pl/programista-8-2018-75/) - write-ups of `production` and `cryptovm` challenges from [Teaser Dragon CTF 2018](https://ctftime.org/event/648), written with my CTF teammates: Gros and Tacet. I was responsible for the `production` challenge where you had to make `open` syscall fail by exceeding the maximum number of opened file descriptors, which were limited by `rlimit` beforehand.
 * [[2018] Never ever to be fooled to pay ransomware! – CTFZone 2018 Quals](https://programistamag.pl/programista-7-2018-74/) - a write-up of a reverse-engineering CTF challenge where we had to decrypt an Android ransomware. Solved and written together with Paweł Łukasik, who also wrote a [write-up on his blog](https://ctfs.ghost.io/never-ever-be-fooled-to-pay-ransomware-ctfzone2018/).
 * [[2016] "IPython -- wygodna interaktywna powłoka Pythona"](https://programistamag.pl/ipython-wygodna-interaktywna-powloka-pythona/) (IPython -- Python enhanced interactive shell) -- describes IPython interactive shell and its features (history, magic commands, configuration, extensions, notebook/Jupyter) -- [article pdf]({{ site.url}}assets/about_me/ipython-article.pdf);

### Work

Looking for a presentation, training, workshop, or just having an interesting project I may be interested in? Contact me or [Trail of Bits](https://www.trailofbits.com/contact/).


### Hobbies

Programming, reverse engineering (or rather looking under the hood to understand how things work), computer security, teaching others, climbing (bouldering) and ice skating.

