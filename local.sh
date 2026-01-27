#!/bin/sh

# Serve the website locally, hit localhost:4000 after that
podman run -it --rm -v `pwd`:/site -p 4000:4000 bretfisher/jekyll-serve
