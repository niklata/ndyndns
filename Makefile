CC = gcc -Wall -Wpointer-arith -Wstrict-prototypes
AR = ar
objects = log.o nstrl.o util.o chroot.o pidfile.o signals.o strlist.o linux.o config.o ndyndns.o

ndyndns : $(objects)
	$(CC) `curl-config --libs --cflags` -o ndyndns $(objects)

ndyndns.o : log.h nstrl.h util.h chroot.h pidfile.h signals.h strlist.h linux.h config.h
	$(CC) $(CFLAGS) $(archflags) $(LDFLAGS) -c -o $@ ndyndns.c

linux.o: log.h strlist.h
config.o: log.h util.h
chroot.o: log.h
pidfile.o: log.h
signals.o: log.h
strlist.o:
nstrl.o:
log.o :

install: ndyndns
	-install -s -m 755 ndyndns /usr/sbin/ndyndns
tags:
	-ctags -f tags *.[ch]
	-cscope -b
clean:
	-rm -f *.o ndyndns
distclean:
	-rm -f *.o ndyndns tags cscope.out

