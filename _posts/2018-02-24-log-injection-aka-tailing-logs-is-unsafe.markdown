---
layout:     post
title:      "Logs injection or why is logs tailing unsafe"
date:       2018-02-24 09:00:30
tags:       security
---

I have been playing with one of Android apps that pushes some messages to logs based on user input recently and I have noticed that `adb logcat` is as bad as `tail -f` when it comes to following logs.

### The problem with _tailing_ logs

Both `adb logcat` and `tail -f` will 'print out' control characters as is - with their appropriate meaning. Lets see an example. Having a log invocation like this:

```python
logging.error("LEFT %s RIGHT", untrusted_input)
```

Assuming the `untrusted_input` is just a `"<untrusted input>"` string, the outputted log may look like:

```
WARN  | 2018-02-24 04:07:20 | SOME TOTALLY UNRELATED MESSAGE BEFORE
ERROR | 2018-02-24 04:07:23 | LEFT <untrusted input> RIGHT
WARN  | 2018-02-24 04:07:25 | SOME TOTALLY UNRELATED MESSAGE AFTER
```

An attacker could spoof this log into another one and then create a new log line to keep things consistent (so they won't leave the `RIGHT` string in a weird position). An example input for that would be:

```
\b\b\b\b\bSome other logging message which looks like a valid one!\nERROR | 2018-02-24 04:07:23 | LEFT lol
```

Note that five `\b` characters have been used to remove the `LEFT ` part and `\n` has been used to get to a new line to produce fake log entry. The final logs, when tailed (`tail -f <logfile>`) would look as:

```
WARN  | 2018-02-24 04:07:20 | SOME TOTALLY UNRELATED MESSAGE BEFORE
ERROR | 2018-02-24 04:07:23 | Some other logging message which looks like a valid one!
ERROR | 2018-02-24 04:07:23 | LEFT lol RIGHT
WARN  | 2018-02-24 04:07:25 | SOME TOTALLY UNRELATED MESSAGE AFTER
```

Of course this kind of attack is not a new thing (e.g. there is an [owasp page about it](https://www.owasp.org/index.php/Log_Injection)). Another thing is there are some conditions that needs to be meet which makes it less dangerous - i.e. the attacker needs to know where is the injection point, what is the log format or timestamp. Still, this could be disastrous if someone parses logs through standard unix tools like `awk` or `grep` line by line e.g. in a cron.

### What to do?

There are some ideas to prevent or stop this issue:

1. You could accept only printable characters as the user input. However this isn't always the case.

2. You could use logs coloring. If the log message part has different color then the metadata before it (log source/level/timestamp) it is much easier to spot the injection. Still it doesn't protect you against injections of `\b` or `\r` control characters.

3. You could pass the input through a `repr`-like function so that all non-printable characters would be escaped and so could be spotted easily. That is how it would look in a Python programming language (here, using `%r` format in logs makes it so that the input is passed through `repr` built-in function):

```python
>>> logging.error("Important log data: %r", "Some fancy log\nNewline won't pass; neither will \r\b\b\b\b\b")
ERROR   | 2018-02-24 03:00:45,011 | root | Important log data: "Some fancy log\nNewline won't pass; neither will \r\x08\x08\x08\x08\x08"
```

Sadly, some other languages out there like C or Java doesn't have a `repr`-like function in their standard library. Still, someone already asked for that on StackOverflow, so [here you can find a C version](https://stackoverflow.com/questions/11601703/python-style-repr-for-char-buffer-in-c) and [here a Java one](https://stackoverflow.com/questions/1350397/java-equivalent-of-python-repr).
