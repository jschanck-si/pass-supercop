#!/bin/bash

DEST=./data/$1_wisdom.dat

factors=( $(factor $1) )
if [ -z "${factors[2]}" ]
then
    L=$(($1-1))
else
    L=$1
fi

echo "Generating FFTW wisdom for transform length $L and storing it in data/$1_wisdom.dat"

if [ -e $DEST ]
then
    read -p "$DEST exists. Overwrite? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        fftw-wisdom --exhaustive rof$L rob$L > $DEST
    fi
else
    fftw-wisdom --exhaustive rof$L rob$L > $DEST
fi

