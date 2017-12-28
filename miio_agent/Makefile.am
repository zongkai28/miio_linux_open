bin_PROGRAMS = miio_agent agent_client
miio_agent_SOURCES = src/miio_agent.c src/miio_json.c src/rbtree.c src/miio_json.h src/miio_agent.h src/rbtree.h

agent_client_SOURCES = src/agent_client.c

miio_agent_LDADD = $(jsonc_LIBS) -ljson-c -lm
miio_agent_CFLAGS = -I. $(jsonc_CFLAGS) -s

agent_client_CFLAGS = -s

distclean-local:
	rm -rf Makefile.in compile autom4te.cache aclocal.m4 config.h.in configure depcomp install-sh missing
