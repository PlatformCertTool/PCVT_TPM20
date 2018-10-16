# The terms of the software license agreement included with any software you
# download will control your use of the software.
#
# INTEL SOFTWARE LICENSE AGREEMENT
#
# IMPORTANT - READ BEFORE COPYING, INSTALLING OR USING.
#
# Do not use or load this software and any associated materials (collectively,
# the "Software") until you have carefully read the following terms and
# conditions. By loading or using the Software, you agree to the terms of this
# Agreement. If you do not wish to so agree, do not install or use the Software.
#
# SEE "Intel Software License Agreement" file included with this package.
#
# Copyright Intel, Inc 2017
#
# Initial Development by TrustPhi, LLC, www.trusiphi.com

TARGET = ../getAndVerifyEK
INCLUDES = -I../
LIBS = -L../ -ltss -lcrypto
CC = gcc
CFLAGS = -g -Wall

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -Wl,-rpath=./ -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
