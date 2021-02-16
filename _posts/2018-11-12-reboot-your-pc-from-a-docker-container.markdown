---
layout:     post
title:      "Reboot your pc from a docker container"
date:       2018-11-12 09:00:30
tags:       security, docker
---

I came back from a [PUT Security Day](https://www.meetup.com/Poznan-Security-Meetup/events/255244492/) where I gave a talk about Docker security. One of the questions I asked myself when preparing the talk is whether one can reboot their PC (aka host machine) from a docker container.

### Rebooting the usual way: `reboot` program

Normally, one would use a `reboot` program to do this task but this program isn't present in many of the docker images.
Let's give it a try with the official `ubuntu` image:

```
$ docker run --rm -it ubuntu reboot
docker: Error response from daemon: OCI runtime create failed: container_linux.go:348: starting container process caused "exec: \"reboot\": executable file not found in $PATH": unknown.
ERRO[0001] error waiting for container: context canceled
```

as we can see, the program isn't in `$PATH`. Let's see another ways of rebooting the container.

### Reeboting with SysRq

It is possible to reboot Linux without any external dependencies by using [SysRq](https://en.wikipedia.org/wiki/Magic_SysRq_key). This can be achieved by first writing to the sysrq and then writing to sysrq-trigger to trigger the action:

```bash
$ echo 1 > /proc/sys/kernel/sysrq
$ echo b > /proc/sysrq-trigger
```

But if we execute it in a docker container, it won't work, because the sysrq is a read-only file system in there:

```
$ docker run --rm -it ubuntu bash
root@c640b157389b:/# echo 1 > /proc/sys/kernel/sysrq
bash: /proc/sys/kernel/sysrq: Read-only file system
```

The thing is, even when we are the `root` user in a docker container (note: and this is the same root as on the host machine) we don't get full capabilities.
Those can be given by rerunning the container with `--privileged` flag:

```
$ docker run --rm -it --privileged ubuntu bash
root@e293a1c415a7:/# echo 1 > /proc/sys/kernel/sysrq
root@e293a1c415a7:/# echo b > /proc/sysrq-triggerERRO[0005] error waiting for container: EOF
```

Running this on my machine actually didn't reboot it but that's because I use Docker for Mac and so all the containers are spawned in a virtual machine used for that purpose.
But the action killed the docker daemon and resulted with such error:

```
Supervisor has failed, shutting down: Supervisor caught an error: one of the children died: com.docker.driver.amd64-linux (pid: 37738)
```

### Rebooting with `reboot` syscall

Another way to execute a reboot is to use a `reboot` syscall. This can be achieved with a short C program:

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/reboot.h>

int main() {
    return reboot(RB_AUTOBOOT);
}
```

Let's try to compile and run it in a docker container.
For a better understanding on what is going on, we will add a `SYS_PTRACE` linux capability to our docker container,
so it will be possible to use `strace`, a linux syscall tracer program, that uses the `ptrace` syscall under the hood.
We will also use `gcc` docker image with `strace` installed on it from apt.

```
$ docker run --rm -it --cap-add=SYS_PTRACE gcc bash
root@dfe469dd8034:/# apt update 2>/dev/null 1>&2 && apt install -y strace 2>/dev/null 1>&2
root@dfe469dd8034:/# printf "#define _GNU_SOURCE\n#include <unistd.h>\n#include <sys/reboot.h>\nint main(){reboot(RB_AUTOBOOT);}" > a.c && gcc a.c
root@dfe469dd8034:/# strace -e reboot ./a.out
reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART) = -1 EPERM (Operation not permitted)
+++ exited with 0 +++
```

It didn't work as we didn't add a `SYS_BOOT` capability (that makes it possible to use `reboot` and `kexec_load` syscalls). If we add it, the `reboot` will kinda work:

```
dc@dc:~$ docker run --rm --cap-add=SYS_PTRACE --cap-add=SYS_BOOT -it gcc bash
root@e5c15796ae6b:/# apt update 2>/dev/null 1>&2 && apt install -y strace 2>/dev/null 1>&2
root@e5c15796ae6b:/# printf "#define _GNU_SOURCE\n#include <unistd.h>\n#include <sys/reboot.h>\nint main(){reboot(RB_AUTOBOOT);}" > a.c && gcc a.c
root@e5c15796ae6b:/# strace -e reboot ./a.out
reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTARTdc@dc:~$
```

It actually killed the docker container but didn't reboot machine the docker is run on (in this case I launched it on a vps).
The reason for that can be found in `man 2 reboot`:

```
   Behavior inside PID namespaces
       Since  Linux  3.4,  if  reboot()  is  called from a PID namespace other than the initial PID namespace with one of the cmd values listed below, it performs a "reboot" of that namespace: the
       "init" process of the PID namespace is immediately terminated, with the effects described in pid_namespaces(7).
```

so the reboot worked, but for the PID namespace the container was in.
A short explanation for those who are not familiar with linux namespaces: this is one of linux kernel features utilized by docker which makes it possible to create isolated groups of given resources (e.g. PIDs, users, mounts and others).
See `man namespaces` for more info.

### Can you use SysRq method without `--privileged` flag?

When I was preparing my talk I wondered if I can launch the SysRq example without the `--privileged` flag.
At first I thought it may be because of lacking the `SYS_BOOT` capability or maybe something with the default seccomp profile the docker uses ([source](https://docs.docker.com/engine/security/seccomp/); as long as your kernel supports seccomp), so I adjusted the flags, but it didn't help:

```
$ docker run --rm --cap-add=SYS_BOOT --security-opt seccomp=unconfined -it gcc bash
root@b6342cab4756:/# echo 1 > /proc/sys/kernel/sysrq
bash: /proc/sys/kernel/sysrq: Read-only file system
```

I thought that maybe some other capability is needed, so I tried adding all of them:

```
$ docker run --rm --cap-add=ALL --security-opt seccomp=unconfined -it gcc bash
root@c4d8b01be2d1:/# echo 1 > /proc/sys/kernel/sysrq
bash: /proc/sys/kernel/sysrq: Read-only file system
```

but all I got is `Read-only file system`.

It turns out this can be hacked by mounting the `/proc` virtual filesystem to be writable:

```
$ docker run --rm -v /proc:/writable_proc -it gcc bash
root@8c1d0f5ed52e:/# echo 1 > /writable_proc/sys/kernel/sysrq
root@8c1d0f5ed52e:/# echo b > /writable_proc/sysrq-trigger
```

...and now it rebooted the machine.

It seems there is no capability to make it possible to write to `/proc`.
[This stackoverflow answer](https://unix.stackexchange.com/a/209361) also states that there are no ACLs for that.

### The end

And that's all of this `reboot` topic here.

In the end, it's good that it is not possible to reboot the host machine with the default settings.
It is possible to do so by using `--privileged` or by mounting the `/proc` virtual filesystem to be writable.
I guess not very much people do that and I hope that if they do, they are aware of the consequences.

EDIT: **Nonetheless, while not necessarily a fault of docker, this is a bad design that it is possible to reboot your host machine while disallowing the `CAP_SYS_BOOT` (or `SYS_BOOT` in docker nomenclature) capability.**

If you ask what was the purpose - just playing with docker and understanding how the things are limited etc.

Also special thanks to [Oshogbo](https://oshogbo.vexillium.org/) for some ideas and discussion about this topic and to [foxtrot\_charlie](https://foxtrotlabs.cc/) and all the PUT Security Day team for inviting me to give a talk there o/.

