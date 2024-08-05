---
layout:     post
title:      "Terrible inet_aton in glibc"
date:       2021-02-16 01:00:00
tags:       c, security, python
---

TLDR: The `man inet_aton` states that "`inet_aton()` returns nonzero if the address is valid, zero if not" ...and so it is sometimes used to check if a string is a valid IP address. **Which should be fine, but isn't, because some implementations are weird**.



Let's see an example C program, that has been linked with glibc and let's run it on Linux:

```c
#include <stdio.h>
#include <arpa/inet.h>

void p(const char* string) {
    struct in_addr pin = {0};
    int result = inet_aton(string, &pin);
    printf("inet_aton(\"%s\") = %d\n", string, result);
}

int main() {
    //  inet_aton(const char *cp, struct in_addr *pin);
    p("1.2.3.4");
    p("1.2.3.4;");
    p("1.2.3.4;ls");
    p("1.2.3.4 ");
    p("1.2.3.4 ;");
    p("1.2.3.4 ;ls");
    p("1.2.3.4 whyyyyyyy this works");
}
```

And the output:
```
$ uname -a
Linux 4.15.0-109-generic #110-Ubuntu SMP Tue Jun 23 02:39:32 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

$ gcc --version | head -n1
gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0

$ gcc inet_aton.c -o inet_aton && ./inet_aton
inet_aton("1.2.3.4") = 1
inet_aton("1.2.3.4;") = 0
inet_aton("1.2.3.4;ls") = 0
inet_aton("1.2.3.4 ") = 1
inet_aton("1.2.3.4 ;") = 1
inet_aton("1.2.3.4 ;ls") = 1
inet_aton("1.2.3.4 whyyyyyyy this works") = 1
```

As we can see, glibc's `inet_aton` will result 1 for strings that starts with valid IP addresses but ends with some garbage.
I have found an explanation for it on [glibc issue 20018 written by Florian Weimer](https://sourceware.org/bugzilla/show_bug.cgi?id=20018):
> This flexible behaviour is allowed because it makes parsing space-separated lists of addresses (as C strings) easier to manage. You advance the pointer between the address blocks and call inet\_aton. In this case getaddrinfo uses inet\_aton to determine the validity of the input string, and so considers "127.0.0.1\r\nspam" a valid name parameter and it is immediately converted into the address structure for 127.0.0.1.

This behavior is also mentioned by [RedHat Bugzilla Bug 1347549](https://bugzilla.redhat.com/show_bug.cgi?id=1347549).

Despite there is a reason for this behavior, I don't think it is good to have it and it is a shame it isn't documented properly in the `inet_aton (2)` manual page.

### How do other projects use that?

I have made some research in 2019 where I looked at some open source projects and found out it was used in Python's `ssl` builtin module and in the `requests` package.
Let's see how they used it.

#### Python's ssl module

The `ssl` module uses `inet_aton` in its `match_hostname` function, that checks if a given hostname matches ssl cert.

While I was not sure if this was an exploitable bug, I and my friend [Paul Kehrer](https://twitter.com/reaperhulk) reported this bug to the Python Security Response Team (PSRT) and it has been fixed in [CPython's PR 14499](https://github.com/python/cpython/pull/14499).

An example showing this issue can be seen below.

```python
In [1]: import ssl

In [2]: cert = {'subjectAltName': (('IP Address', '1.1.1.1'),)}

In [3]: ssl.match_hostname(cert, '1.1.1.1')

In [4]: ssl.match_hostname(cert, '1.1.1.2')
---------------------------------------------------------------------------
SSLCertVerificationError                  Traceback (most recent call last)
<ipython-input-4-2c3754a67e0d> in <module>
----> 1 ssl.match_hostname(cert, '1.1.1.2')

/usr/lib/python3.7/ssl.py in match_hostname(cert, hostname)
    325         raise CertificateError("hostname %r "
    326             "doesn't match %r"
--> 327             % (hostname, dnsnames[0]))
    328     else:
    329         raise CertificateError("no appropriate commonName or "

SSLCertVerificationError: ("hostname '1.1.1.2' doesn't match '1.1.1.1'",)

In [5]: ssl.match_hostname(cert, '1.1.1.1 ; /bin/ls this works')

In [6]: # yes, it passed the check!
```

#### Python requests library

In Python's requests module, the `inet_aton` is used in utils in the `address_in_network`, `is_ipv4_address` and `is_valid_cidr` functions:

```python
In [1]: import requests

In [2]: requests.utils.address_in_network('1.1.1.1', '1.1.1.1/24')
Out[2]: True

In [3]: requests.utils.address_in_network('1.1.1.1wtf', '1.1.1.1/24')
---------------------------------------------------------------------------
OSError                                   Traceback (most recent call last)
<ipython-input-3-ca74bb828961> in <module>
----> 1 requests.utils.address_in_network('1.1.1.1wtf', '1.1.1.1/24')

/usr/lib/python3/dist-packages/requests/utils.py in address_in_network(ip, net)
    552     :rtype: bool
    553     """
--> 554     ipaddr = struct.unpack('=L', socket.inet_aton(ip))[0]
    555     netaddr, bits = net.split('/')
    556     netmask = struct.unpack('=L', socket.inet_aton(dotted_netmask(int(bits))))[0]

OSError: illegal IP address string passed to inet_aton

In [4]: requests.utils.address_in_network('1.1.1.1 wtf', '1.1.1.1/24')
Out[4]: True

In [5]: requests.utils.is_ipv4_address('1.1.1.1 disconnect3d was here...')
Out[5]: True

In [6]: requests.utils.is_valid_cidr('1.1.1.1 obviously not but yes/24')
Out[6]: True
```

I reported this issue to requests in [requests#5131](https://github.com/psf/requests/issues/5131) which is still open, more than 1.5 years from reporting it.

### Summary

There are probably more projects that rely on `inet_aton` which may introduce security bugs.

I guess that cases like this may be another reason why companies like [Google are thinking about implementing their own libc](https://lists.llvm.org/pipermail/llvm-dev/2019-June/133269.html).

We should never trust libs without checking the implementation and whether they are tested properly, especially if we want to use them to validate untrusted input.
Such testing could be done via formally verifying a function. As an example this could be done here by using Trail of Bits [DeepState](https://github.com/trailofbits/deepstate) project and adding tests to check if an input containing invalid characters can result in `inet_aton` returning 1.

Also, thanks to [@bl4sty](https://haxx.in/), who showed this `inet_aton` weird case at his talk at [WarCon 2019](http://warcon.pl/) conference and to [Paul Kehrer](https://twitter.com/reaperhulk), who helped me to report this to Python Security Response Team (PSRT).

*NOTE: This post was initially written in 2019, but I finally finished it and hit publish in 2021.*
