---
layout: post
title:  "Google CTF 2016 - For2 [Forensics]"
date:   2016-05-01 22:02:10
tags:   ctf, forensics
excerpt_separator: <!--more-->
---

This is a writeup from Google CTF 2016 - For2 task from forensics category.

We have got a [`capture.pcapng`]({{ site.url }}assets/ctf_google2016/capture.pcapng) file, which is a sniffed USB traffic from an usb mouse (yeah, you can capture it e.g. with [Wireshark](https://www.wireshark.org/)).
<!--more-->
After loading it into Wireshark, we can see some configuration messages (first screen) - saying that the connected device is a mouse and later on a lot of messages from mouse to the host (second screen - hmm... mouse coordinates?).

![Wireshark - configuration messages]({{ site.url }}assets/ctf_google2016/wireshark.png)

![Wireshark - mouse coordinate messages]({{ site.url }}assets/ctf_google2016/wireshark2.png)

As we can see on the second screen there are 4 `Leftover Capture Data` bytes. We thought that it might be the coordinates of mouse movement and/or buttons it presses.

After some googling I've found an [USB specification pdf]({{ site.url }}assets/useful/usb_specification.pdf), in which under mouse I have found information on how the mouse sends data (page 71):

![Mouse coordinates messages specification]({{ site.url }}assets/ctf_google2016/mouse_msg_spec.png)

Okay... so I thought that those 4 `Leftover Capture Data` bytes might actually be this data.

So I exported it into a text file using `tshark`:

```bash
tshark -r "capture.pcapng" -T fields -e usb.capdata -Y usb.capdata > mouse_clicks.txt
```

This gave a rather big file, which looked like this:

```
00:00:c7:4b:5d:39:00:00
00:00:b5:4b:5d:39:00:00
02
02
02
00:01:fe:00
00:01:ff:00
00:02:00:00
00:03:00:00
00:01:00:00
00:02:00:00
00:04:ff:00
00:01:ff:00
00:03:ff:00
00:03:fd:00
00:02:ff:00
00:01:ff:00
00:04:fd:00
00:01:fd:00
00:00:fd:00
...
```

I removed first 5 lines of it (the first message with 4 `Leftover Capture Data` had `00:01:fe:00` value) and wrote a simple Python script to parse this data and create a png image:

```python
#!/usr/bin/env python

from PIL import Image
import ctypes

width = 2048
height = 2048
img = Image.new("RGB", (width, height))

red = (0, 0, 0) # Skipping Right Mouse Btn, its not needed at all
green = (0, 255, 0)
blue = (0, 0, 255)
default = (0, 0, 0)

colormap = {
    0: red,
    1: green,
    2: blue
}
x = width/2
y = height/2

with open('mouse_clicks.txt') as f:
    for line in f:
        bytes = map(lambda v: int('0x'+v, 16), line.split(":"))
        b0, b1, b2, b3 = bytes

        # byte0: 0==LBM, 1=RBM, 2=MBM
        color = colormap.get(b0, default)

        # byte1: X displacement
        x_dis  = ctypes.c_int8(b1).value

        # byte2: Y displacement
        y_dis = ctypes.c_int8(b2).value

        x = x + x_dis
        y = y + y_dis

        #print "line = ", line, "bytes =", bytes, x, y

        img.putpixel((x, y), color)

img.save("image.png")
```

Which gave image containing flag - and so 200 points:

![Flag image]({{ site.url }}assets/ctf_google2016/flag.png)
