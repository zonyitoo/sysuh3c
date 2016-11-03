# SYSU H3C Client

A CLI H3C Client for [OpenWRT](http://openwrt.org)

*Only tested in SYSU east campus*

## Compilation

### Compile with OpenWRT-SDK

* First you should get the **OpenWRT-SDK**. See [here](http://wiki.openwrt.org/zh-cn/doc/howto/obtain.firmware.sdk) for more detail.

* Then `cd` into the SDK directory

```bash
git clone git@github.com:zonyitoo/sysuh3c.git -b openwrt package/sysuh3c
```

* Modify sysuh3c/Makefile

```makefile
define Package/$(PKG_NAME)
    ...
    PKGARCH:=[arch]
endef
```

* You will get the `sysuh3c_[version]-1_[arch].ipk` in `bin/[arch]/package`

## Usage

```bash
-h --help        print help screen
-u --user        user account
-p --password    password
-i --iface       network interface (default is eth0)
-m --method      EAP-MD5 CHAP method [xor/md5] (default xor)
-d --daemonize   daemonize
-c --colorize    colorize
-l --logoff      logoff
```
