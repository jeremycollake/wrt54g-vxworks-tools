#!/bin/sh
if [ $# = 4 ]; then
	if [ ! -f "/tmp/part2.bin" ]; then
		cp /etc/bsptools/part2.bin /tmp/part2.bin
	fi
	./bsptool /mac1 $1 /mac2 $2 /mac3 $3 /serial $4 /tmp/part2.bin
else
	echo "Incorrect usage."
	echo "$0: mac1 mac2 mac3 serial"
fi


