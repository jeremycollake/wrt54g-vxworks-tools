#!/bin/sh
echo WARNING: flashing VxWorks boot loader.. do not abort this process! Wait!
mtd erase nvram
mtd -f write /etc/bsptools/part1.bin mtd0
mtd -f -r write /tmp/part2.bin mtd1

