# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Support for pihole FTL
LUCI_DESCRIPTION:=Luci interface for FTL configuration

PKG_MAINTAINER:=regae <regae.yassin@gmail.com>

LUCI_DEPENDS:=+pihole-FTL +pihole
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
