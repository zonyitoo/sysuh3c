#CFLAGS= -Wall -Os -Ofast
#LDFLAGS= -Os -Ofast
CFLAGS += -luci
LDFLAGS += -luci

sysuh3c: main.o eapauth.o eaputils.o md5.o
	$(CC) $(LDFLAGS) $^ -o $@

main.o: main.c eapauth.h eapdef.h
	$(CC) $(CFLAGS) -c -o $@ $<

eapauth.o: eapauth.c eapauth.h eapdef.h
	$(CC) $(CFLAGS) -c -o $@ $<

eaputils.o: eaputils.c eaputils.h eapdef.h
	$(CC) $(CFLAGS) -c -o $@ $<

md5.o: md5.c md5.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o sysuh3c
