#!/bin/bash

if ! command -v proot &>/dev/null; then
    echo "proot is not installed. Exiting script. [❌]"
    exit 1
fi

root_home_dir="/data/data/com.termux/files/root-home"
default_home_dir="/"

if [ -d "$root_home_dir" ] && [ -r "$root_home_dir" ] && [ -w "$root_home_dir" ]; then
    home_dir="$root_home_dir"
else
    home_dir="$default_home_dir"
    echo "The $root_home_dir directory is not accessible [⚠️]"
fi

if [ "$#" -gt 0 ]; then
    proot -0 --verbose=0 -w "$home_dir" "$@" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "Command not recognized or failed: $1 [❌]"
    fi
else
    echo -e "\nFalse shell root executed [✔️]\n"
    proot -0 --verbose=0 -w "$home_dir" /system/bin/sh
fi
