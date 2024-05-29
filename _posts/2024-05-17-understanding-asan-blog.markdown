---
layout:     post
title:      "Understanding AddressSanitizer blog post"
date:       2024-05-16 17:00:00
tags:       posts, publications
---

Some time ago during an audit I found an out-of-bounds bug that was not detected by AddressSanitizer.


I wondered why this happened and this spawned a whole research in Trail of Bits where we extended the 
AddressSanitizer bug detection capabilities in LLVM (libc++) for the `std::string` and `std::deque` collections 
by annotating them (so ASan is aware of their size vs capacity bounds). 
We also added support for all allocators for all the containers that have container overflow detections (vector, string, deque). 
Apart from that, we also improved some other internals of ASan.


When we did this research, we initially made a talk about this on the [WarCon conference in 2022](https://docs.google.com/presentation/d/1cVoQUtB9d0kNPZMx1EsQ5C37ElDmg29s4mSpi6g3vyM/). 
Now, when we got our improvements merged into LLVM, we wrote a full blog post about all of the improvements made, ASan internals, its limitations and quirks.


You can read about all of this in the 
["Understanding AddressSanitizer: Better memory safety for your code"](https://blog.trailofbits.com/2024/05/16/understanding-addresssanitizer-better-memory-safety-for-your-code/) 
blog post I released at Trail of Bits blog with Dominik Klemba.
