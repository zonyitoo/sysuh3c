# CLI H3C Client

A CLI H3C Client for [OpenWRT](http://openwrt.org)

## Compilation

* First we need the OpenWRT-Toolchain

Enter the package [site](http://downloads.openwrt.org/snapshots/trunk/) and choose the right architecture. And then you will see the **Toolchain** package at the front of the list.

or you can download it directly from the URL below. Just replace the `[arch]` to a valid architecture name. `ar71xx` for example.

```
http://downloads.openwrt.org/snapshots/trunk/[arch]/OpenWrt-Toolchain-[arch]-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2.tar.bz2
```

* After you got the toolchain.

``` bash
tar -xjf OpenWrt-Toolchain-[arch]-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2.tar.bz2

## set your PATH
export PATH=/path/to/your/toolchain/bin:$PATH
# Example: PATH=~/OpenWrt-Toolchain-ar71xx-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/bin:$PATH

## set the STAGING_DIR variable
export STAGING_DIR=/path/to/your/toolchain
# Example: STAGING_DIR=~/OpenWrt-Toolchain-ar71xx-for-mips_r2-gcc-4.6-linaro_uClibc-0.9.33.2
```

* After that. You can run make to compile the source.

```
make
```

* Then you will get the executable file `clih3c`. Just upload it to your router and run it.

## Usage

```bash
-h --help        print help screen
-u --user        user account
-p --password    password
-i --iface       network interface (default is eth0)
-d --daemonize   daemonize
```
