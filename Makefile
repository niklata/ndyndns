CC = gcc -Wall -Wpointer-arith -Wstrict-prototypes
AR = ar
objects = log.o nstrl.o util.o chroot.o pidfile.o signals.o strlist.o linux.o config.o ndyndns.o

ndyndns : $(objects)
	$(CC) $(LDFLAGS) `curl-config --libs --cflags` -o ndyndns $(objects)

ndyndns.o : log.h nstrl.h util.h chroot.h pidfile.h signals.h strlist.h linux.h config.h
	$(CC) $(CFLAGS) $(archflags) -c -o $@ ndyndns.c

linux.o: log.h strlist.h
config.o: log.h util.h
chroot.o: log.h
pidfile.o: log.h
signals.o: log.h
strlist.o:
nstrl.o:
log.o :

install: ndyndns
	-install -s -m 755 ndyndns /usr/local/sbin/ndyndns
	-install -m 644 ndyndns.1.gz /usr/local/man/man1/ndyndns.1.gz
	-install -m 644 ndyndns.conf.5.gz /usr/local/man/man5/ndyndns.conf.5.gz
tags:
	-ctags -f tags *.[ch]
	-cscope -b
clean:
	-rm -f *.o ndyndns
distclean:
	-rm -f *.o ndyndns tags cscope.out

