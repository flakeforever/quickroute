prefix=/usr

OBJS	= quickroute.o config.o
SOURCE	= quickroute.cpp config.cpp
HEADER	= 
OUT	= quickroute
CC	 = g++
FLAGS	 = -g -c -Wall -std=c++11
LFLAGS	 = -luci -lstdc++

all : quickroute
.PHONY : clean

quickroute : quickroute.o config.o
	$(CC) -g quickroute.o config.o -o quickroute $(LFLAGS)

quickroute.o: quickroute.cpp
	$(CC) $(FLAGS) quickroute.cpp 

config.o: config.cpp
	$(CC) $(FLAGS) config.cpp 

clean:
	rm -f $(OBJS) $(OUT)

install: quickroute
# install -m 0755 $(OUT) $(prefix)/sbin

uninstall:
# rm -f $(prefix)/sbin/$(OUT)
