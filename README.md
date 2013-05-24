# CLI H3C Client

A CLI H3C Client for [OpenWRT](http://openwrt.org)

## Compilation

### Compile with OpenWRT-SDK

* First you should get the **OpenWRT-SDK**. See [here](http://wiki.openwrt.org/zh-cn/doc/howto/obtain.firmware.sdk) for more detail.

* Then `cd` into the SDK directory

```bash
git clone git@github.com:zonyitoo/clih3c.git -b openwrt package/clih3c
make
```

* You will get the `clih3c_0.1-1_ar71xx.ipk` in `bin/ar71xx/package`

## Usage

```bash
-h --help        print help screen
-u --user        user account
-p --password    password
-i --iface       network interface (default is eth0)
-d --daemonize   daemonize
```
