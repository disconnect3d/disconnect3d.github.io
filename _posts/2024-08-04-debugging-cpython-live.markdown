---
layout:     post
title:      "Debugging already running Python scripts via GDB" 
date:       2024-08-04 17:13:37
tags:       python, debugging, programming
---

A friend of mine had an interesting case recently where they wanted to debug an already running Python script on Linux:

![friend post]({{ site.url }}assets/posts/ian-attach-python-debugger.png)

And after some testing it turned out this is possible, so let's see how it can be done in CPython :).

## Few notes on CPython

CPython, the reference implementation of the Python programming language, is written in the C programming language. Under the hood, it is a virtual machine that interprets (executes) so called "Python bytecode" which is the instruction set of the virtual machine. For curious readers, some of the CPython 3.11 instruction handling code can be found in the [ceval.c](https://github.com/python/cpython/blob/3.11/Python/ceval.c#L1754-L5835) file in CPython's GitHub repository.

Since `python` is just a native program, we can debug it with a native debugger like GDB. Now, this is completely different than debugging the Python code itself (e.g., via [`pdb`](https://docs.python.org/3/library/pdb.html), the Python debugger) but... as we will see, we can achieve it through GDB.

## Debugging already running Python script

Let's assume we have the following Python script that we will run with Python 3.11.6 on Ubuntu 23.10:

```py
import time

# Let's assume SECRET is sth we would like to find out
# with a debugger
from secret import SECRET

def mysleep(i):
    print(f"Going to sleep... = {i}")
    time.sleep(1)

i = 0
while True:
    i += 1
    mysleep(i)
```

Now, if we run this script, we can attach to the Python interpreter process via the GDB ([The GNU Project debugger](https://sourceware.org/gdb/)) debugger by using its `attach <pid>` command:

![attaching GDB to python process]({{ site.url }}assets/posts/cpython-attach-gdb.png)

The GDB also asked me if I want additional debug information for the python program, which I accepted (`Enable debuginfod for this session? (y or [n]) y`).
This made GDB download debugging symbols so that we can see much more information during debugging. 
We can see this in the output of the `backtrace` command which shows the call stack of the process. If we didn't have debug symbols, we would only see a few names instead of the whole trace.

Now, in order to debug the Python code with pdb, I found out that we can set a breakpoint on a `PyEval_SaveThread` function, continue the execution until it is called and then call a `PyRun_SimpleString` function to call arbitrary Python code in the context of the currently executed frame. For what is worth, those "frames" are objects that represent the execution state of Python code. I believe that each function call would create a new frame object.

Let's see this in action:

![running breakpoint() in attached GDB]({{ site.url }}assets/posts/cpython-attached-breakpoint.png)

As we can see, we eventually executed PDB in the console where the script was running, achieving our goal!

## Conclusion

While this has worked here in my and my friend's case, I must admit that I would not recommend running this on production. 
I have only tested this method on Python 3.11.6 and generally speaking, I am not sure if this doesn't corrupt the internal CPython state somehow -- and if it does -- this could end up crashing our script.

Another issue is that if the Python script is running without a terminal, we would probably need to hijack its stdin and stdout objects so that we could actually provide input for it and receive the output.

Written all this, I still find this trick interesting and I bet we could create some solution that would work properly and would be more convenient. 
But that's maybe for another time :).

I would also like to thanks Ian Smith from Trail of Bits for an interesting problem to solve :)
