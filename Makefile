.PHONY: all clean

CFLAGS=-I../lib -I../src -Wall -Werror -ggdb 

all : auth_plugin_md5.so 

auth_plugin_md5.so : auth_plugin_md5.c
	$(CC) ${CFLAGS} -fPIC -shared $^ -o $@ 

clean :
	rm -f *.so *.test
