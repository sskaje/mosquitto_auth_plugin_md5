.PHONY: all clean

DEBUG_OPT=-DMQAP_DEBUG
CFLAGS=-I../lib -I../src -Wall -Werror -ggdb 

all : auth_plugin_md5.so 

auth_plugin_md5.so : auth_plugin_md5.c
	$(CC) ${CFLAGS} -fPIC -shared $^ -o $@ 

debug: auth_plugin_md5_debug.so

auth_plugin_md5_debug.so : auth_plugin_md5.c
	$(CC) ${CFLAGS} ${DEBUG_OPT} -fPIC -shared $^ -o $@ 


clean :
	rm -f *.so *.test
