# this makefile is for linux, use cl for Windows and undefine _LINUX
INCLUDEDIR = .
CC=g++
CFLAGS = -O3 -D_LINUX

all: wrt_vx_imgtool

wrt_vx_imgtool: 
	$(CC) $(CFLAGS) wrt54gv5_img.cpp -o $@
	
clean:
