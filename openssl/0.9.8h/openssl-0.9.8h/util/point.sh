#!/bin/sh

rm -f "$2"
if test "$OSTYPE" = msdosdjgpp; then
    cp -fp "$1" "$2"
else
    ln -s "$1" "$2"
fi
echo "$2 => $1"

