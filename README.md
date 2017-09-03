# SYSU H3C Client

A SYSU H3C Client in \*NIX

## Usage

`sysuh3c` uses `SCons` build system.

```bash
$ cd src
$ scons -Q
$ scons install
```

Then you get `sysuh3c` executable file in `/usr/local/bin`.

```bash
-h --help        print help screen
-u --user        user account (must!)
-p --password    password
-i --iface       network interface (default is eth0)
-m --method      EAP-MD5 CHAP method [xor/md5] (default xor)
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
