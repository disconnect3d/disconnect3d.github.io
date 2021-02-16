---
layout:     post
title:      "Gynvael's PL stream 006 mission solution"
date:       2017-06-29 19:50:30
tags:       gynvaelstream, stegano, python
---

This is a writeup to small stegano task from [Gynvael Coldwind's polish stream](https://www.youtube.com/watch?v=w-7vLvTKJbI) 6th mission (there are small tasks at the end of his livestreams).

The original mission description can be seen below (but it is in polish):

```
MISJA 006            goo.gl/te47XT                  DIFFICULTY: ███░░░░░░░ [3/10]
┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅
Przeglądając stare dokumenty z lat '60 zeszłego wieku natrafiliśmy na taką oto
notatkę:

  c5 c2 c3 c4 c9 c3 40 82 a8 93 82 a8 40 86 81 91 95 a8 40 87 84
  a8 82 a8 40 82 a8 93 40 93 96 87 89 83 a9 95 a8 4b 40 c1 93 85
  40 95 89 85 40 91 85 a2 a3 4b

Przypuszczamy, że to jakieś zdanie w języku Polskim, ale nie udało nam się tego
zdekodować. Zrzucimy to więc na Ciebie. Powodzenia!

--

Odzyskaną wiadomość umieśc w komentarzu pod tym video :)
Linki do kodu/wpisów na blogu/etc z opisem rozwiązania są również mile
widziane!

P.S. Rozwiązanie zadania przedstawie na początku kolejnego livestreama.
```

To sum up the task shortly: the `c5 c2 c3...` string is a sentence written in polish language but with some weird encoding. We have to decode it somehow.

I have started the task by looking for different encodings on Wikipedia... and ended up trying all of them in IPython interactive shell:

```python
In [1]: a = '''c5 c2 c3 c4 c9 c3 40 82 a8 93 82 a8 40 86 81 91 95 a8 40 87 84
   ...:   a8 82 a8 40 82 a8 93 40 93 96 87 89 83 a9 95 a8 4b 40 c1 93 85
   ...:   40 95 89 85 40 91 85 a2 a3 4b'''

In [2]: a = [int('0x%s' % s, 16) for s in a.split()]

In [3]: b = ''.join(map(chr, a))

In [4]: import encodings, string

In [5]: y = encodings.aliases.aliases.keys()

In [6]: for enc in y:
   ...:     try:
   ...:         msg = b.decode(enc)
   ...:         if all(c in string.printable for c in msg):
   ...:             print("{} --> '{}'".format(enc, msg))
   ...:     except:
   ...:         pass
   ...:     
1140 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ebcdic_cp_wt --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ebcdic_cp_he --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ibm1140 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
csibm1026 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ibm1026 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
csibm500 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ibm424 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ibm500 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ebcdic_cp_us --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ebcdic_cp_nl --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
037 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
424 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ibm039 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ibm037 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
1026 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
csibm424 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ebcdic_cp_ch --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ebcdic_cp_be --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
csibm037 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
500 --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
ebcdic_cp_ca --> 'EBCDIC bylby fajny gdyby byl logiczny. Ale nie jest.'
```

Seems that there are many encodings that either work similar/inherit from EBCDIC or are just aliases for it.
