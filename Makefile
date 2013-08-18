CXXFLAG = -c -std=c++11 -Wall -O2

all: sysuh3c

sysuh3c: eapauth.o main.o eapdef.o eaputils.o
	$(CXX) $^ -o $@

eapauth.o: eapauth.cpp eapauth.h eapdef.h
	$(CXX) $(CXXFLAG) $< -o $@

main.o: main.cpp eapauth.h eapdef.h
	$(CXX) $(CXXFLAG) $< -o $@

eapdef.o: eapdef.cpp eapdef.h
	$(CXX) $(CXXFLAG) $< -o $@

eaputils.o: eaputils.cpp eaputils.h eapdef.h
	$(CXX) $(CXXFLAG) $< -o $@

clean:
	rm -f *.o
