#!/bin/sh

# fill2stroke.sh
# Convert fills to strokes in PDF document - can sometimes reveal hidden text 
# that could be an indicator of fraud

# Author: Joe Stewart
# Copyright (C) 2016 SecureWorks

# Depends on pdf2ps, sed, ps2pdf

# Test: Run script against ac9e24f047fb86294c64082d778c7845 on VT

FILE=$1

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <pdf file>"
	exit
fi

pdf2ps $FILE ${FILE}.f2stmp
if [ $? -ne 0 ]; then
	echo ${0}: An error occurred, check pdf2ps output
	exit
fi
sed 's/^f$/s/' ${FILE}.f2stmp | sed 's/^f\*$/s /' > ${FILE}.edit.f2stmp
ps2pdf ${FILE}.edit.f2stmp ${FILE}.f2s.pdf
if [ $? -eq 0 ]; then
	echo Wrote ${FILE}.f2s.pdf
else
	echo ${0}: An error occurred, check ps2pdf output
fi
rm ${FILE}.f2stmp ${FILE}.edit.f2stmp

