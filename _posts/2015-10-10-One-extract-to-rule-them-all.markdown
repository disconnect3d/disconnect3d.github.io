---
layout:     post
title:      "One extract to rule them all"
date:       2015-10-10 19:44:01
tags:       bash
---

From time to time everyone has to extract an archive. When living in a command line the problem of such task is to remember all of the arguments to every of the tools/programs that let you extract different types of archives.

One day I wished there would be a tool that would work with all archives and so I have written a handy bash function that you can find below.

To *install* it just place it in a file that is launched with your shell (e.g. `~/.bashrc` if you are using `bash`). The usage is pretty simple - `extract <filename>` - the script will extract the archive into `<filename without extension>` directory.

```bash
function extract() {
    if [ $# -ne 1 ]; then
        echo "Usage: $FUNCNAME filename"
    fi
    
    filename=$1
    if [ -f $filename ]; then
        case $filename in
            *.tar.xz)   tar xvfJ "$filename"                          ;;
            *.tar.gz)   tar --gzip -xvf "$filename"                   ;;
            *.tar.bz2)  tar --bzip2 -xvf "$filename"                  ;;
            *.tar)      tar -xvf "$filename"                          ;;
            *.tgz)      tar --gzip -xvf "$filename"                   ;;
            *.tbz2)     tar --bzip2 -xvf "$filename"                  ;;
            *.bz2)      bunzip2 "$filename"                           ;;
            *.7z)       7za x "$filename"                             ;;
            *.Z)        uncompress --keep "$filename"                 ;;
            *.zip)      unzip $filename -d "${filename%.*}"           ;;
            *.rar)      unrar x "$filename"                           ;;
            *.jar)      jar xf "$filename"                            ;;
            *)          echo "'$filename' not supported extension"    ;;
        esac
    else
        echo "'$filename' is not a file."
    fi
}
```
