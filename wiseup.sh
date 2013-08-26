#!/bin/bash

OUT="$(mktemp)"

factors=( $(factor $1) )
if [ -z "${factors[2]}" ]
then
    echo "Sure you didn't mean $(($1-1))?"
    exit
fi

echo "Generating FFTW wisdom for PASS-$(($1+1)) and storing it in data/$1_wisdom.dat"

fftw-wisdom --exhaustive rof$1 rob$1 > $OUT

if [ $? -eq 0 ]
then
    mv -i $OUT ./data/$1_wisdom.dat
else
    rm $OUT
fi

