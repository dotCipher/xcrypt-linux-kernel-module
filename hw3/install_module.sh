#!/bin/sh
lsmod
rmmod sys_xcrypt
insmod sys_xcrypt.ko
lsmod
