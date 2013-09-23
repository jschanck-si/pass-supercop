#!/bin/bash

DEST=./data/$1_wisdom.dat
N=$1

factors=( $(factor $1) )
if [ -z "${factors[2]}" ]
then
    N=$(($N-1))
fi

echo "Generating FFTW wisdom for transform length $N and storing it in data/$1_wisdom.dat"

if [ -e $DEST ]
then
    read -p "$DEST exists. Overwrite? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]
    then
        fftw-wisdom --exhaustive rof$1 rob$1 > $DEST
    fi
else
    fftw-wisdom --exhaustive rof$1 rob$1 > $DEST
fi

