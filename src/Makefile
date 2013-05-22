#CXXFLAGS= -Wall -Os -Ofast
#LDFLAGS= -Os -Ofast

#CXX=mips-openwrt-linux-g++

clih3c: main.o eapauth.o
	$(CXX) $(LDFLAGS) $^ -o $@

main.o: main.cpp eapauth.h eapdef.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

eapauth.o: eapauth.cpp eapauth.h eapdef.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f *.o clih3c
