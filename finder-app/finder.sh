#!/bin/sh

X=0
Y=0


if [ $# -lt 2 ]; then
    echo "error, too few arguments"
    exit 1
fi

if [ ! -d $1 ]; then
    echo "error, directory $1 does not exist"
    exit 1
fi

X=$(find $1 -type f 2>/dev/null | wc -l)

Y=$(grep -r $2 $1 2>/dev/null | wc -l)

echo  "The number of files are $X and the number of matching lines are $Y" 



