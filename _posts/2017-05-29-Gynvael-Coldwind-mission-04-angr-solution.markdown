---
layout:     post
title:      "Gynvael's PL stream 004 mission solved with angr"
date:       2017-05-29 00:30:30
tags:       gynvaelstream, angr
---

This is an angr writeup to a "spaghetti code" task from [Gynvael Coldwind's polish stream](https://www.youtube.com/watch?v=CR1kLHxMMmg) 4th mission (there are small tasks at the end of his livestreams).

The original mission description can be seen below (but it is in polish):

```
MISJA 004            goo.gl/                     DIFFICULTY: ███░░░░░░░ [3/10]
┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅
Jeden z naszych agentów infiltruje siedzibę wrogiego syndykatu, i utknął pod
drzwiami z elektronicznym zamkiem. Udało mu się dostać do elektroniki i zrzucić
krótki program, który sprawdza wprowadzony kod i otwiera drzwi.

Twoim zadaniem będzie wykonanie analizy poniższego programiku oraz znalezienie
poprawnego kodu.

      #include <stdio.h>
      int check(char*b){char*p;for(p=b;*p;p++);if(((p-b)^42)!=47)return(
      ~0xffffffff);unsigned long long ch=0x1451723121264133ULL;for(p=b;*
      p;p++)ch=((ch<<9)|(ch>>55))^*p;return!!(14422328074577807877ULL==
      ch);}int main(void){char buf[1234];scanf("%1233s",buf);puts("nope"
      "\0good"+check(buf)*(6-1));return 0;}

--

Odzyskaną wiadomość umieśc w komentarzu pod tym video :)
Linki do kodu/wpisów na blogu/etc z opisem rozwiązania są również mile
widziane!

P.S. Rozwiązanie zadania przedstawie na początku kolejnego livestreama.
```

The task idea is to find an input that would print out "good" for above code.

Lets first see the code formatted and highlighted:
```c
#include <stdio.h>

int check(char*b) {
    char*p;

    for(p=b; *p; p++);
    if(((p-b)^42) != 47)
        return (~0xffffffff);

    unsigned long long ch = 0x1451723121264133ULL;

    for(p=b; *p; p++)
        ch = ((ch<<9) | (ch>>55)) ^ *p;

    return !!(14422328074577807877ULL == ch);
}

int main(void) {
    char buf[1234];

    scanf("%1233s",buf);

    puts("nope""\0good"+check(buf)*(6-1));

    return 0;
}
```

We can see a `scanf` that saves up to 1233 non-white space characters and a terminating null byte (`'\0'`) in `buf` buffer.

But is it the real length of input we should provide? The buffer is then passed to `check` function which we would like to return 1 - so that the address of `"nope\0good"` string would be incremented by `1*(6-1) = 5` characters and `good` would be printed out.


The `check` function first increments `p` pointer up to the end of passed `b` buffer (which is `buf`):

```c
for(p=b; *p; p++)
```

Then there is a condition `(p-b)^42 != 47` which if true (1 in terms of C language), returns `(~0xffffffff)` which is just 0 - one could calculate it in head, or using a C program. We can do it in Python as well with the help of `ctypes` module:
```python
>>> import ctypes
>>> ctypes.c_int32(~0xffffffff).value
0
```

(Yeah, this assumes that `int` is actually 32 bits - which might not be true - but on most PCs it will be).

Anyway, as we don't want to return 0 from the function, we want the condition to be evaluated to false (0 in terms of C language).

The `p-b` in the equation is just the length of string (`buf` buffer). The expression uses [XOR](https://en.wikipedia.org/wiki/Exclusive_or) operation (`^` in C) which can be inversed by itself. So `length ^ 42 != 47` is the same as `length != 42 ^ 47`.

This can be calculated in head or in Python:
```python
>>> 42^47
5
```

So now we know, that the string must contain 5 non null byte characters.

From now instead of solving the rest manually, I just used [angr](http://angr.io/) and its symbolic execution capabilities.


To use angr, I had to modify a bit above C code, so the symbolic execution engine would have easier job. Here is the modified code:
```c
#include <stdio.h>

int check(char*b){
    char*p;

    for(p=b;*p;p++);
    if(((p-b)^42)!=47)
        return(~0xffffffff);

    unsigned long long ch=0x1451723121264133ULL;
    for(p=b;*p;p++)
        ch=((ch<<9)|(ch>>55))^*p;

    return!!(14422328074577807877ULL==ch);
}

int main(void){
    char buf[20];
    scanf("%20s",buf);

    if (check(buf))
        return 0x1337;

    return 0;
}
```

I have changed the code a bit so that I will be able to say the symbolic execution solver to find a way to have 0x1337 value returned from main. To do it, we need to compile the code first - `gcc main.c -o exec` and then find the address of instruction when main is going to return 0x1337. We can do it by using `objdump`:

```bash
$ objdump -Mintel -d ./exec | grep -C3 1337
      4005e0:	48 89 c7             	mov    rdi,rax
      4005e3:	e8 3e ff ff ff       	call   400526 <check>
      4005e8:	85 c0                	test   eax,eax
      4005ea:	74 07                	je     4005f3 <main+0x35>
--->  4005ec:	b8 37 13 00 00       	mov    eax,0x1337           <---
      4005f1:	eb 05                	jmp    4005f8 <main+0x3a>
      4005f3:	b8 00 00 00 00       	mov    eax,0x0
      4005f8:	c9                   	leave  
      4005f9:	c3                   	ret    
```

(I have marked the line found by grep with `--->` and `<---`).

So now we have to tell angr to make its job. This can be done with such code:
```python
import angr

# Address of `mov eax, 0x1337` instruction in main
WIN_ADDR = 0x4005ec

# Load the binary
p = angr.Project('./exec')

# Create initial program state for analysis
# This will begin the analysis from program's Entry Point
state = p.factory.entry_state()

# Construct a path group, so we can perform symbolic execution
pg = p.factory.path_group(state)

# Explore paths and find way to get into WIN_ADDR
results = pg.explore(find=WIN_ADDR)

# Get found path from PathGroup object
found = results.found[0]

# Get symbolic engine from found path
se = found.state.se

# This would return us just one solution:
#   se.any_str(found.state.posix.get_file(0).all_bytes())
# As well as this:
#   found.state.posix.dumps(0)

# We can get more of them but it would be good to limit their length. However,
# I couldn't find a way to add a stdin's length constraint to the solver before exploration.
# Anyway, I came up with getting X solutions for given stdin's length

# Getting stdin's BitVector symbolic value
# (bv.symbolic is True)
bv = found.state.posix.get_file(0).all_bytes()

# The BitVector can be sliced using bits,
# So this is what we have to do to get next 6 characters:
stdin_length = 6

from_bit = len(bv)-1
to_bit = len(bv) - stdin_length * 8

stdin_limited = bv[from_bit:to_bit]

# se.any_n_str will give us up to N solutions
print("Printing out found solutions:")
for idx, solution in enumerate(se.any_n_str(stdin_limited, 100)):
    print('{:2}: {!r}'.format(idx, solution))
```

I hope that the script is self-explanatory. By running it we get the solutions:
```bash
$ python crack.py
Printing out found solutions:
 0: '\xb8\xa8GW!\x00'
 1: 'G\xa8G\xa8!\x00'
 2: 'GW\xb8\xa8!\x00'
 3: '\xb8\xa8\xb8\xa8!\x00'
 4: 'G\xa8GW\xde\x00'
 5: '\xb8WG\xa8!\x00'
 6: 'GW\xb8W\xde\x00'
 7: 'G\xa8\xb8W!\x00'
 8: '\xb8W\xb8\xa8\xde\x00'
 9: '\xb8\xa8\xb8W\xde\x00'
10: 'GWGW!\x00'
11: 'GWG\xa8\xde\x00'
12: '\xb8\xa8G\xa8\xde\x00'
13: '\xb8W\xb8W!\x00'
14: '\xb8WGW\xde\x00'
15: 'G\xa8\xb8\xa8\xde\x00'
```

NOTE: The intended solution was `GWGW!` but as you can see there are some other solutions that contain non-printable characters. We can test them by using Python:
```python
from subprocess import Popen, PIPE

TASK_BINARY = './main'

solutions = (
    '\xb8\xa8GW!\x00', 'G\xa8G\xa8!\x00', 'GW\xb8\xa8!\x00', '\xb8\xa8\xb8\xa8!\x00',
    'G\xa8GW\xde\x00', '\xb8WG\xa8!\x00', 'GW\xb8W\xde\x00', 'G\xa8\xb8W!\x00',
    '\xb8W\xb8\xa8\xde\x00', '\xb8\xa8\xb8W\xde\x00', 'GWGW!\x00', 'GWG\xa8\xde\x00',
    '\xb8\xa8G\xa8\xde\x00', '\xb8W\xb8W!\x00', '\xb8WGW\xde\x00', 'G\xa8\xb8\xa8\xde\x00'
)

for s in solutions:
    p = Popen([TASK_BINARY], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate(s)
    assert stderr == ''

    print('Stdout for {!r} is {!r}'.format(s, stdout))
```

And the output is:
```
$ python test_solutions.py
Stdout for '\xb8\xa8GW!\x00' is 'good\n'
Stdout for 'G\xa8G\xa8!\x00' is 'good\n'
Stdout for 'GW\xb8\xa8!\x00' is 'good\n'
Stdout for '\xb8\xa8\xb8\xa8!\x00' is 'good\n'
Stdout for 'G\xa8GW\xde\x00' is 'good\n'
Stdout for '\xb8WG\xa8!\x00' is 'good\n'
Stdout for 'GW\xb8W\xde\x00' is 'good\n'
Stdout for 'G\xa8\xb8W!\x00' is 'good\n'
Stdout for '\xb8W\xb8\xa8\xde\x00' is 'good\n'
Stdout for '\xb8\xa8\xb8W\xde\x00' is 'good\n'
Stdout for 'GWGW!\x00' is 'good\n'
Stdout for 'GWG\xa8\xde\x00' is 'good\n'
Stdout for '\xb8\xa8G\xa8\xde\x00' is 'good\n'
Stdout for '\xb8W\xb8W!\x00' is 'good\n'
Stdout for '\xb8WGW\xde\x00' is 'good\n'
Stdout for 'G\xa8\xb8\xa8\xde\x00' is 'good\n'
```

So... this was an unintended way to solve Gynvael Coldwind's 4th mission. There is a [writeup](https://dsp.krzaq.cc/post/574/misja-gynvaela-004/) for the 'standard way' of solving it from KrzaQ. Unfortunately it is in polish.
