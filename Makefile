CXXFLAGS=-Wall -L/home/zonyitoo/clih3c/src/OpenWrt-Toolchain-ar71xx-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/lib
LDFLAGS=-L/home/zonyitoo/clih3c/src/OpenWrt-Toolchain-ar71xx-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/lib

clih3c: main.o eapauth.o
	$(CXX) $(LDFLAGS) $^ -o $@ $(LIBS)

main.o: main.cpp eapauth.h eapdef.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

eapauth.o: eapauth.cpp eapauth.h eapdef.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f *.o clih3c
