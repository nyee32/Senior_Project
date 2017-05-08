#!/bin/bash

echo "Cleaning..."
make clean -f Makefile.am.sample

echo "Compiling..."
make -j12 -f Makefile.am.sample

echo "Making .a file"
ar rcs asn1c.a *.o
