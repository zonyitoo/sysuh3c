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
-b --broadcast   broadcast address (default 01:80:c2:00:00:03)
-i --iface       network interface (default is eth0)
-m --method      EAP-MD5 CHAP method [xor/md5] (default xor)
-d --daemonize   daemonize
-c --colorize    colorize
-l --logoff      logoff
```

## Pre-compiled Binaries

------

### BCM53xx (all)

`sysuh3c_0.3.1-1_bcm53xx.ipk` - for all BCM53xx Products ( Phicomm K3 etc. )

##### Usage

`sysuh3c -u your_name -p your_password -i your_interface -b random_address -d`

##### About the Bug

Some BCM53xx chips are delivered with a bugged RoboSwitch technology - 802.1x EAPOL filtering and that causes 802.1x EAPOL requests being silently discarded, which is essential for authenticating. 

However, that problem only applies to `01:80:c2:00:00:03`, which is the `Nearest non-TPMR Bridge Group address` defined in IEEE Std 802. Fortunately H3C works with almost all addresses so choosing another broadcast address could work. ( I'm using `11:45:14:19:19:81` and it's works fucking well )

ref: https://dev.openwrt.org/ticket/1862

------

### BCM53xx (w/o Roboswitch)

`sysuh3c_0.3-1_bcm53xx.ipk` - for BCM53xx Products without RoboSwitch Bug

This version have no `-b` flag as it's unnecessary.

##### Usage

`sysuh3c -u your_name -p your_password -i your_interface -d`









