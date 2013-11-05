# SYSU H3C Client

A SYSU H3C Client in \*NIX

## Usage

We use GNU Automake build system. Run following commands under the root directory.

```bash
$ ./configure
$ make
$ sudo make install
```

Then you get `sysuh3c` executable file in `/usr/local/bin`.

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
