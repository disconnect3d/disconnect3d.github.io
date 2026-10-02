---
layout:     post
title:      "The tilde in your PATH may not be your HOME"
date:       2026-10-02 11:00:00
tags: [shell, bash, zsh, security]
excerpt_separator: <!--more-->
---

I was playing with the [nono](https://nono.sh/) agent sandboxing tool and it greeted me with a warning: `PATH entries the sandbox can write to: ~/.local/bin/` which looked suspicious.

![nono warning about PATH entries the sandbox can write to]({{ site.url }}assets/posts/tilde-in-path-nono-warning.png)

<!--more-->

In other words, doing this:

```sh
export PATH="$PATH:~/.local/bin/"
```

Will not expand the `~` (tilde) into the home path (or `$HOME`) as the tilde to home expansion happens only in unquoted inputs, as also the [bash documentation says](https://www.gnu.org/software/bash/manual/html_node/Tilde-Expansion.html):

> If a word begins with an unquoted tilde character ('~'), all of the characters preceding the first unquoted slash (...) are considered a tilde-prefix.

So instead of having `/home/<user>/.local/bin/` added to `PATH` we end up with `./~/.local/bin/` added to `PATH`.

And to fix this, we can do this:
```sh
export PATH="$PATH:$HOME/.local/bin/"
```

Note that the unquoted version `export PATH=$PATH:~/.local/bin` actually works in Bash and Zsh, because tilde expansion is also performed in variable assignments after `=` and after each `:`. But relying on that is fragile — one day you add quotes "for safety" and silently break it — so just use `$HOME`.


The whole problem can also be seen in here:

```sh
$ ls -la
total 0
drwxr-xr-x@   2 dc  staff    64 Oct  2 13:37 .
drwxr-x---+ 105 dc  staff  3360 Oct  2 13:37 ..
$ mkdir -p ./~/.local/bin/
$ printf '#include <stdio.h>\nint main() { puts("hello"); }'>a.c; gcc a.c -o ./~/.local/bin/kek
$ PATH="~/.local/bin/" kek
hello
$ tree -f
.
├── ./~
│   └── ./~/.local
│       └── ./~/.local/bin
│           └── ./~/.local/bin/kek
└── ./a.c

4 directories, 2 files
```

![Demo showing that a literal tilde in PATH resolves to a ./~/ directory in the current working directory]({{ site.url }}assets/posts/tilde-in-path.png)

As we can see, the `kek` binary was found and executed from `./~/.local/bin/` — the home directory was never involved.

## Check your PATH

You can quickly check whether you have this problem with:

```sh
$ echo "$PATH" | grep -- '~'
```

or, to see each entry on its own line:

```sh
$ echo "$PATH" | tr ':' '\n' | grep '~'
~/.local/bin/
```

If it prints anything, go fix your `.bashrc`/`.zshrc`/`.profile` and replace the `~` with `$HOME` :).


Btw, kudos to the nono tool for warning about this - even though the warning could be more verbose (PR incoming).
