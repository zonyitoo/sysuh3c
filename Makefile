include $(TOPDIR)/rules.mk

PKG_NAME:=sysuh3c
PKG_VERSION:=0.2
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/sysuh3c
    SECTION:=utils
    CATEGORY:=Utilities
    DEPENDS:=+libc +libgcc +libuci
    TITLE:=Comand Line for SYSU H3C
    PKGARCH:=ar71xx
    MAINTAINER:=zonyitoo
endef

define Package/sysuh3c/description
    A CLI client for H3C.
endef

define Package/luci-app-sysuh3c
    SECTION:=luci
    CATEGORY:=LuCI
    SUBMENU:=3. Applications
    TITLE:=LuCI Web Configuration Page for SYSU H3C
    DEPENDS:=+sysuh3c
    PKGARCH:=all
    MAINTAINER:=simpleyyt
endef

define Package/luci-app-sysuh3c/description
	This package only contains LuCI configuration page for sysuh3c.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/sysuh3c-luci/install
endef

define Package/sysuh3c/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sysuh3c $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(CP) $(PKG_BUILD_DIR)/sysuh3c.conf $(1)/etc/config/sysuh3c
endef

define Package/sysuh3c/prerm
	#!/bin/sh
	if [ -f /var/run/sysuh3c.pid ]; then
		cat /var/run/sysuh3c.pid | while read SYSUH3C_LOCK; do kill -int $(SYSUH3C_LOCK); done
		rm -f /var/run/sysuh3c.pid
	fi
endef

define Package/luci-app-sysuh3c/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller

	$(INSTALL_BIN) ./files/root/etc/init.d/sysuh3c $(1)/etc/init.d/sysuh3c
	$(INSTALL_DATA) ./files/root/usr/lib/lua/luci/model/cbi/sysuh3c.lua $(1)/usr/lib/lua/luci/model/cbi/sysuh3c.lua
	$(INSTALL_DATA) ./files/root/usr/lib/lua/luci/controller/sysuh3c.lua $(1)/usr/lib/lua/luci/controller/sysuh3c.lua
endef


$(eval $(call BuildPackage,luci-app-sysuh3c))
$(eval $(call BuildPackage,sysuh3c))