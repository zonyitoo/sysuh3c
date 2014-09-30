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

* You will get the `sysuh3c_[version]-1_[arch].ipk` and `luci-app-sysuh3c_[version]-1_[arch].ipk` in `bin/[arch]/package`

## Packages

 * `sysuh3c_0.2-1_ar71xx.ipk` :  SYSU H3C comand line tool (without luci web configuration page) for ar7xx based router.
 * `sysuh3c_0.2-1_ramips.ipk` :  SYSU H3C comand line tool (without luci web configuration page) for ramips based router.
 * `luci-app-sysuh3c_0.2-1_all.ipk` : LuCI Web Configuration Page for SYSU H3C (for all architecture).

## Install

 * Install the sysuh3c package. (skip if you haveinstalled)
 * Install the luci-app-sysuh3c package.
 * You have to restart the router.
 
## Usage

### Web Configuration

 * After installed and restarted, you find the sysh3c web configuration page in `Network -> SYS H3c`.
 * Save & Apply.
 
### sysuh3c

```bash
-h --help        print help screen
-u --user        user account
-p --password    password
-i --iface       network interface (default is eth0)
-d --daemonize   daemonize
-c --colorize    colorize
-l --logoff      logoff
```