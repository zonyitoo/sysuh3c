# SYSU H3C Client

A SYSU H3C Client in \*NIX

## Usage

We use CMake Build System.

```bash
$ mkdir build
$ cd build
$ cmake ..
$ make
$ make install
```

Then you get `sysuh3c` executable file in `/usr/local/bin`.

If you get errors about missing `iconv.h` while compiling, you should install iconv library or remove `--enable-showmessage`.

```bash
-h --help        print help screen
-u --user        user account (must!)
-p --password    password
-i --iface       network interface (default is eth0)
-d --daemonize   daemonize
-c --colorize    colorize
```

## Another version for OpenWRT
Now is avaliable on **Branch OpenWRT**

## Known Bugs

## TODOs

* <del>Port to Mac OS X</del> Require for testing.

## Thanks

* [YaH3C](https://github.com/humiaozuzu/YaH3C)
