NAME=bin_nes
R2_PLUGIN_PATH=./radare2/plugins
CFLAGS=-g -fPIC $(shell pkg-config --cflags r_bin) $(R2_INCLUDE)
LDFLAGS=-shared $(shell pkg-config --libs r_bin)
OBJS=$(NAME).o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: $(LIB)

clean:
	rm -f $(LIB) $(OBJS)

$(LIB): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	cp -f bin_nes.$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/bin_nes.$(SO_EXT)
 
