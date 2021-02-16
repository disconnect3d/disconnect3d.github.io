---
layout: page
title: My talks
permalink: /talks/
---

Below you can see a list of talks or workshops I have given for various events along with slides/videos/materials links. If the particular record has a `[PL]` before it - it means it was made in Polish language.

The convention for a given event is `date - name, location`. The `[lightning talk]` tag means the talk took ~5 minutes and was probably prepared just before presenting it or during the event, as an idea to cotribute some more ;).

### 2020.12.17 - A Midwinter Night's Con 2020 ([https://absoluteappsec.com/cons/midwinter-2020/]())[
* Various interesting (and not) bugs case studies ([video](https://www.youtube.com/watch?v=cSb1ZWFhE1w), [slides](https://docs.google.com/presentation/d/1VpXqzPIPrfIPSIiua5ClNkjKAzM3uKlyAKUf0jBqoUI)) - In this talk I will present a "cstrnfinder" research where I found many (stupid) bugs related to string operations in C. Apart from that, we will look through an insufficient permission check that allowed for kASLR bypass within kernel modules in certain container environments. We will also analyse a not sufficient mitigation in glibc allocator, where changing a few lines of code can make it harder for attackers to exploit buggy applications.

### 2020.04.25 - Python Pizza, remote @ your couch ([link](https://remote.python.pizza/))
* [EN] [lightning talk] sudo python is a trap, use isolated mode ([video](https://www.youtube.com/watch?t=2530&v=sOXVxjPjF9E), [slides](https://docs.google.com/presentation/d/11HV4e0wqXxl_9xTpHBKfON6oUJP6MBaj9pUjNP6ETdw)) - a showcase of the "Readline module loading in interactive mode" Python security bug :)

### 2019.11.14-15 - Security PWNing Conference 2019, Warsaw, Poland ([link](https://www.instytutpwn.pl/konferencja/pwning/))
* [PL] Attacking via Linux's procfs, and Countermeasures for App Developers ([slides](https://docs.google.com/presentation/d/1OmrIAxrfDoCFPd0Iw7uQYsUKJhDny-zYCN5F96K7DgY/)) - presentation about procfs, the things you can find there, some consequences of those (consider e.g. arbitrary file reads, directory listings with path traversals in both web apps and programs run by users on the system), weird corner cases when depending on `readlink /proc/PID/exe` or reading process name from comm or cmdline files, PIDs (which are not process handles) and PID-reuse attacks and some mitigations along with the new one - pidfd. Also talked about procfs mount options - hidepid and gid.

### 2019.11.07 - Affinity Tech Talks, Kraków, Poland ([link](https://www.akamaiaffinity.com/))
* [EN] Semantic safety won't save you ([slides](https://docs.google.com/presentation/d/1AZp7ovWBwBHm4UcsPsr1zIuwkNiY2AO68WhzK1m1q0w/)) showed a sample of security traps in Python, Go and C programming languages. The topic comes from the fact that both Python and Go handle the hard stuff (e.g. memory/threading/errors/etc) for us and people often consider them "safe" because of the semantics of the language. Though... we still shoot ourself in the foot despite that "safety". Also thanks to [@b0bbytabl3s](https://twitter.com/b0bbytabl3s) for helping up with this topic :).

### 2019.09.28 - Noc Informatyka 1.2, Kraków, Poland ([link](https://nocinformatyka.pl/))
* [PL] Bebechy kontenerów Dockerowych oraz Grand Theft Ucieczki z uprzywilejowanych kontenerów ([slides](https://docs.google.com/presentation/d/1CZiv5QpAKYqox5eGyrITk712l6cPybZrq3msH5g4gv8/)) - the same presentation as the one made on AlligatorCon. The title ended up too baity though.

### 2019.09.12-15 - PyConPL 2019, Zawiercie, Poland ([link](https://pl.pycon.org/2019/en/))

* Python internals - how does CPython work? ([slides](https://docs.google.com/presentation/d/1EZlxdYMLykCFd9BYz6ZnnbebKmIs4LCD4xkGixkfwGs/)) - a ~2h talk I gave in polish at AGH; it is a deep dive into CPython and its VM. From the original description: "We will learn about CPython bytecode, PYC files, how to disassemble a Python function or decompile it back from bytecode to Python code. We will look at the flow between launching and executing a Python script. We will also go through CPython VM execution by emulating the execution of a short Python function.".
* Python internals - let's talk about dicts - the same talk I gave at Pykonik Tech Talks #43.
* [lightning talk] Regexes WT#? ([slides](https://docs.google.com/presentation/d/1Fo9tOk8xJFrLEXabyNxH6-u2t-QcwG5tkWLlAHxoA90/)) - showed a DoS in Django web framework, wrong regex in Signal-Desktop I found which didn't have a direct security impact and reminded about `re.VERBOSE` flag.
* [lightning talk] PagedOut! ([slides](https://docs.google.com/presentation/d/1zv2mhLRJUfYaDSUClAd5Kg4iQFwrkDw1K37FtLs21Sc/) - described the [PagedOut! free zine](https://pagedout.institute/) and my article about hacking Python's ellipsis
* [lightning talk] Python security issues ([slides](https://docs.google.com/presentation/d/15VI1Uilukb6bCw6wEhNQxAw85dc5f-zLToZoxH8IL7o/) - an overview over random existing Python security bugs.
* [lightning talk] Pyyaml WT# (no slides) - a rant about PyYaml module: there was a 4.1 relase that changed `safe_load` into `load` which was [reverted](https://github.com/yaml/pyyaml/commit/ccc40f3e2ba384858c0d32263ac3e3a6626ab15e) and [removed](https://github.com/yaml/pyyaml/issues/192) from [pypi...](https://github.com/yaml/pyyaml/issues/190), then 5.1 was supposed to make `load` safer by default but not necessarily disallowing it to deserialize Python objects, [so it is stil insecure](https://github.com/yaml/pyyaml/issues/321).
* [lightning talk] A story of a 3d nickname ([slides](https://docs.google.com/presentation/d/1MhsfHxMWtfedxBPWIgE53oHb-5WOg82RahIqKafuGSo/) - a story about '3d' origin in my nickname and something about IRC communities o/.

### 2019.08.16-17 - AlligatorCon Europe 2019, Budapest, Hungary ([link](https://www.alligatorcon.eu/))

* Fancy "privileged" Docker container escapes ([slides](https://docs.google.com/presentation/d/1tCqmGSOJJzi6ZK7TNhbzVFsTekvjvQR8GGPoaYBrM1o)) - a detailed introduction to the Linux kernel features used by Docker (namespaces, cgroups, capabilities, seccomp, AppArmor) and some info about "privileged" escapes. Note: What does privileged mean? I discuss this matter and show that one of escapes can be pointed down to `--cap-add=SYS_ADMIN --security-opt apparmor=unconfined` and explore this environnment more.

### 2019.05.30 - AGH, Kraków, Poland ([event link](https://www.facebook.com/events/2192736794372737/))

* [PL] How does CPython work ([slides](https://docs.google.com/presentation/d/1JWRcds_nJByQTz9JaS5ijhjYqbu9W3NkFbt8BUOKZJ0)) - a ~2h talk going deeply into how CPython VM works, giving an example of emulating it and explaining some of the CPython internals.

### 2019.03.28 - Pykonik Tech Talks #43, Kraków, Poland - [streaming](https://www.facebook.com/pykonik/videos/374580079800185/)

* Python internals - let's talk about dicts ([slides](https://docs.google.com/presentation/d/1jVhSF_YnR-z0_1ftsQWjluYZxiaq2xDX3kSouDbccP8/)) - a ~45 min talk where we show some different aspects of Python dicts, like hashing, a weird case of hashing -1 value, issues when hashing mutable values or overwriting dicts, examples of extending dicts and an interesting case of updating dicts with not overriding already existing keys' values.

### 2019.02.12 - Empire Hacking, New York ([link](https://www.empirehacking.nyc/) or [meetup link](https://www.meetup.com/Empire-Hacking/events/257665554/))

* Low level debugging with Pwndbg - [slides](https://docs.google.com/presentation/d/1mDfA_27DtLUkOaTZ8U9kF1aJcOhpixnGD8hDrLyKR6w/) - more robust version of this talk; demo examples [here](https://docs.google.com/presentation/d/1bbzmZ0OYPR7SNozpV5jF0c2ors47X2thvoCzC3Kqeoc).

### 2018.11.19-20 - Security PWNing Conference 2018, Warsaw, Poland ([link](https://www.instytutpwn.pl/konferencja/pwning2018-eng/#:~:text=Low%20level%20debugging,Pwndbg))

* [PL] Low level debugging with Pwndbg - [slides](https://docs.google.com/presentation/d/1odAM9Rw2-fMI4cGgBWJWnfqMtzJz-NHmXWa5ksJ4rMk/)

### 2018.11.10 - PUT Security Day, Poznań, Poland ([link](https://www.meetup.com/Poznan-Security-Meetup/events/255244492/))

* [PL] Docker security - [slides](https://docs.google.com/presentation/d/1khzyfemmeoqNrUbsd4Sp6wF-rLfFSanLZaKeCcE8BtU); talk given in Polish (slides were in English). The video can be found [here](https://www.youtube.com/watch?v=GnGMz3Bx0vY&list=PLSfzNwWc8jhTLLhhWvCqi_Fo2NX1K9Ci1&index=3).

### 2018.10.25 - Pykonik Tech Talks #39 Kraków, Poland ([link](https://www.meetup.com/Pykonik/events/255574318/))

* Docker security (see slides from PUT Security Day) - is root in the container the same as on host? Is it safe to add untrusted user to docker group? How to make your app running in a container safer?

### 2018.10.15 - 4Developers Kraków, Kraków, Poland ([link](https://krakow.4developers.org.pl/))

* Let's play: Code Review - [slides](https://docs.google.com/presentation/d/1q4ktLHiK6_-xQqzG84caNSP4Ejxs585Lq_FCefzDAEU/)

### 2018.09.27 - Pykonik Tech Talks #38, Kraków, Poland ([link](https://www.meetup.com/Pykonik/events/254438400/))

* [lightning talk] Soft and hard links on Linux: symbolic and physical links - demo about links and some flaws around it (long paths, interesting links in /proc etc) - there were no slides

### 2018.08.01 - AlligatorCon 2018 ([link](https://www.alligatorcon.eu/index-2018.html#Talks))

* Python Reversing Challenge - [slides](https://docs.google.com/presentation/d/1P55nqXej8GSrOXQRrdSnd7SuIOPl_tBwJvnMqvWsLrs/)

### 2018.08.23-26 - PyCon PL 2018, Ossa, Poland ([link](https://pl.pycon.org/2018/))

* Insecure Things to Avoid in Python - [slides](https://docs.google.com/presentation/d/1LTIuStnvlKvkyRdpFmXrJ6-fxYE0roU_gHJ-83nk0zU/) - consists of the one from ThaiPy + info about how I hosted my ['Python-challenges'](https://python-challenges.com/) challenge
* [lightning talk] Random cool stuff in Python - [slides](https://docs.google.com/presentation/d/1ZaqkKDkAQoXbM-SYnc8F8XmdA1jgirI8pb2nXSl_2PI/) - `__dict__`, `__slots__`, `exec` usages in CPython (`namedtuple` and Python's 3.7 dataclasses use those)
* [lightning talk] How does CPython work? - [slides](https://docs.google.com/presentation/d/1_C2bapgRyxxSxOeW-CdSdOGzBC1v1GyXUugzlPQPy2c/)
* [lightning talk] How to be a better developer - [slides](https://docs.google.com/presentation/d/1aBsyLrKRqcj87iZ8mUl_CNjFOBvNNJstJStCZhAITlc/)
* [lightning talk] Decrypting Android Ransomware - [slides](https://docs.google.com/presentation/d/1_IqTmHe-Uz9a-FisK_CQ7F7QIImwJNrXWTzRKHVWoqA/)
* [lightning talk-ish] "I hate Portals" aka ReverseMe challenge - [slides](https://docs.google.com/presentation/d/1ARiS5JSu9u4LGbiveSVY4Uzo27aHuw--lwCr8JKtEFU/) - a talk about some cool solutions to my ['Python-challenges'](https://python-challenges.com/) challenge

### 2018.06.09 - Noc Informatyka 1.1, Kraków, Poland ([link](https://nocinformatyka.pl/poprzednie-edycje/#:~:text=Dominik,Python))

* Some insecure Things to Avoid in Python - [slides](https://docs.google.com/presentation/d/1i-iHdoJzMTXuqBEiiHzALy4I9mtFH-GpaPSsl2DuyC4/edit?usp=sharing) - pickle, yaml, eval (and its pseudosandbox) and safeeval

### 2018.04.19 - Thai Py, Bangkok, Thailand ([link](https://www.meetup.com/ThaiPy-Bangkok-Python-Meetup/events/ftssdpyxgbqb/))

* Let's play code review: how to write better python code first time - [slides](https://docs.google.com/presentation/d/10IqFIef1msnxU0mzdTiW4prm_SGC07EAp7FC4Jumil4)

### 2018.02.08 - Thai Py, Bangkok, Thailand ([link](https://www.meetup.com/ThaiPy-Bangkok-Python-Meetup/events/246228255/))
* Insecure Things to Avoid in Python - [slides](https://docs.google.com/presentation/d/1SJyjXuenqReI4SpRJ5fXWLWB9zICfU9NLb1d0s6e9Hk/)
* [lightning talk] Unix wildcards gone wild (see link from PyCon PL 2016)

### 2017.08.25-26 - AlligatorCon PL 2017, Kraków, Poland ([link](https://www.alligatorcon.eu/index-2017.html#Talks))

* Python as a hacker's toolbox vol 2 - [slides](https://docs.google.com/presentation/d/1oHD8X9-qqJzEcMI94C05uzEqTnX8P4VqeDv1pIaLAxY/)

### 2017.08.17-20 - PyCon PL 2017, Ossa, Poland ([link](https://pl.pycon.org/2017/index_en.html))

* Python as a hacker's toolbox vol 2 - [slides](https://docs.google.com/presentation/d/1oHD8X9-qqJzEcMI94C05uzEqTnX8P4VqeDv1pIaLAxY/)
* [lightning talk] A simple step for better security when using Python - [slides](https://docs.google.com/presentation/d/1kulgvzQ5vxnmHlmy8Kz9bN-uzhutIcMJ8TCLeBJ9XtA/)
* [lightning talk] Python AST rewriting: 'how does PyTest do that' - [slides](https://docs.google.com/presentation/d/1wIFInPCSN-i03YSmDIIzJ4JAAzZiujFLFauNleXtaMA)

### 2016.12.05 - Code Europe Cracow 2016, Kraków, Poland ([link](https://crossweb.pl/wydarzenia/code-europe-cracow/); note: conference link ~expired)

* [PL] Capture The Flag: interesting way of spending time - [slides](https://docs.google.com/presentation/d/1k85e6xYnTKPbkkxTvCHO9YbmEPsze7HRzhNG67RXFLI)

### 2016.10.13-16 - PyCon PL 2016, Ossa, Poland ([link](https://pl.pycon.org/2016/index_en.html))

* [lightning talk] Capture The Flag - [slides](https://docs.google.com/presentation/d/1dP9_QSI4aCHb2MtSVH9iEnnXP4HvrzU5EYl5q35__y8)
* [lightning talk] Unix wildcards gone wild - [slides](https://docs.google.com/presentation/d/1ielgFWmmKWDNlgXYVgiIy2j1ncGNm43qD47ypzl8VAs)

### 2016.06.03 - Noc informatyka 1.0, Kraków, Poland ([link](http://nocinformatyka.pl/historia.html#2016))

* [PL] Unusual debugging tools - [slides and examples](https://github.com/disconnect3d/unusual_dbg_presentation)

### 2012-2017 - KNI Kernel Computer Science Organisation, AGH UST, Kraków, Poland

* [PL] CTFs - similar talk to the one at Code Europe conference
* [PL] Shells, buffering and IPython - [slides](https://docs.google.com/presentation/d/1pJ-MNWSE7vatkYejR4_713G9DSh6P_aIuNWJGs3Umzc)
* [PL] How to learn IT - [slides](https://docs.google.com/presentation/d/10Lka0sY_SEeGQ04jGFpT2O-9l4HBXqdm4kTbUSnXJiY/)
* [PL] Not working for me either - debugging tools for Linux and Windows - no slides, covered GDB debugging, linux tracers (ltrace, strace), Valgrind, Windows Sysinternals, Dependency Walker and debugging through IDEs - PyCharm and Visual Studio. Done with my friend [Alex](https://github.com/Alexander3).
* [PL] Python from scratch course, held with my friend [Alex](https://github.com/Alexander3); [materials](https://github.com/disconnect3d/kni-kernel-python-course).
* [PL] CTF workshops (2016, 2017) - many different topics, mainly low level ones but not only; see [materials](https://github.com/JustHitTheCore/ctf_workshops).

### 2016-2017 - for various university classes assignments at AGH UST, Kraków, Poland
* [PL] SQLi, XSS, CSRF: some vulnerabilities from web applications - [slides](https://github.com/disconnect3d/websec_presentation/blob/master/websec.pdf) - presented and demoed about some vulns and exploitation techniques for web applications. Co-authored with Magdalena Jaroszyńska.
* [PL] 1/3: Reverse engineering and finding and exploitting bugs in native apps for x86/x86\_64 - [slides](https://docs.google.com/presentation/d/1HKuW69NFD2IFSdkdD7ul3aWriHXHDLfPOvJV0wsiwH0) - introduction presentation to show up my master thesis topic for a diploma seminar. Described few low level concepts - processor registers, x86 assembly basic instructions, the `call`, `leave`, `ret` instrtuctions flow and some bug sources in applications.
* [PL] 2/3: Reverse engineering and finding and exploitting bugs in native apps for x86/x86\_64 - [slides](https://docs.google.com/presentation/d/1rWcOBc2dSUCzCfc1IXQSUWYopQ6eX4Cgc4yLg4cpA5Y/) - mid-semester presentation; showed a process of solving a reverse-engineering CTF challenge: from inspecting the binary, deassembling it, decompiling it via IDA Pro, inspecting program's strings, finding the winning condition, dynamic analysis via debbugging to find out which global values corresponds to which game objects and solving winning-condition equations through Z3 theorem prover. The talk also shown how code instrumentation, here address sanitizer, helps finding bugs, how a stack-buffer-overflow can be exploited, how to find out ELF binaries mitigations and various techniques an attacker can use to exploit bugs (shellcodes, overwriting GOT, ROP chains).
* [PL] 3/3: Reverse engineering and finding and exploitting bugs in native apps for x86/x86\_64 - [slides](https://docs.google.com/presentation/d/1j5ws3G7YLxeezjmPrEG9Q-iFD3GLsrpXi1wW7h7NAwo/) - a summary presentation where I showed how ELF maps to memory, listed processes for finding bugs, described fuzzing and symbolic execution, showed an interesting heap-related bug and more.


