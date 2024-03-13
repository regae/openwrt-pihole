#
# Copyright (C) 2021-2022 OpenWrt.org
#
# This is free software, licensed under European Union Public License v1.2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pihole-FTL
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/pi-hole/FTL
PKG_SOURCE_VERSION:=2f38061f02d17dc2efa19a493b9f7f68baaedb65
PKG_MIRROR_HASH:=7457061fd7327a681b62a20227226efeb87505d23c722672592e82d80cfb65f7

PKG_VERSION:=6.0-$(call version_abbrev,$(PKG_SOURCE_VERSION))

CMAKE_INSTALL:=1

PKG_MAINTAINER:=Regi Yassin <regae.yassin@gmail.com>
PKG_LICENSE:=EUPL-1.2
PKG_LICENSE_FILES:=LICENSE

PKG_CONFIG_DEPENDS:= CONFIG_pihole_FTL_ipset \
	CONFIG_pihole_FTL_conntrack \
	CONFIG_pihole_FTL_shared_sqlite \
	CONFIG_pihole_FTL_shared_cjson \
	CONFIG_pihole_FTL_readline \
	CONFIG_pihole_FTL_nftset \
	CONFIG_pihole_FTL_tls_mbedtls \
	CONFIG_pihole_FTL_tls_openssl \
	CONFIG_pihole_FTL_build_doc

PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-lto
PKG_SSP:=0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_OPTIONS += -DSHARED_TRE=ON -DFORCE_STATIC_LIB=OFF -DCMAKE_BUILD_TYPE:String="RELWITHDEBINFO" \
	$(if $(CONFIG_pihole_FTL_build_doc),-DBUILD_DOCS=ON,-DBUILD_DOCS=OFF) \
	$(if $(CONFIG_pihole_FTL_tls_mbedtls),-DTLS_MBEDTLS=ON,-DTLS_MBEDTLS=OFF) \
	$(if $(CONFIG_pihole_FTL_tls_openssl),-DTLS_OPENSSL=ON,-DTLS_OPENSSL=OFF) \
	$(if $(CONFIG_pihole_FTL_ipset),-DIPSET_SUPPORT=ON,-DIPSET_SUPPORT=OFF) \
	$(if $(CONFIG_pihole_FTL_conntrack),-DCONNTRACK_SUPPORT=ON,-DCONNTRACK_SUPPORT=OFF) \
	$(if $(CONFIG_pihole_FTL_shared_sqlite),-DSHARED_SQLITE=ON,-DSHARED_SQLITE=OFF) \
	$(if $(CONFIG_pihole_FTL_shared_cjson),-DSHARED_CJSON=ON,-DSHARED_CJSON=OFF) \
	$(if $(CONFIG_pihole_FTL_readline),-DUSE_READLINE=ON,-DUSE_READLINE=OFF) \
	$(if $(CONFIG_pihole_FTL_nftset),-DNFT_SUPPORT=ON,-DNFT_SUPPORT=OFF)

ifeq ($(CONFIG_BUILD_NLS),y)
CMAKE_OPTIONS += -DBUILD_NLS=ON -DSTAGING_DIR=$(STAGING_DIR)
endif

export WEB_VERSION=$(PKG_VERSION)
export CORE_VERSION=$(PKG_VERSION)
export FTL_BRANCH=$(shell git --git-dir=$(TOPDIR)/.git rev-parse --abbrev-ref HEAD)
export FTL_VERSION=$(PKG_VERSION)
export FTL_ARCH=$(ARCH)
export FTL_HASH=r23512-c22931b653
export FTL_DATE=$(shell git --git-dir=$(TOPDIR)/.git show -s --format=%ci)

# KERNEL_EXT4_FS_SECURITY is needed if using linux capabilities (setcap/getcap)
define Package/pihole-FTL
  SECTION:=net
  CATEGORY:=Network
  TITLE:=The Pi-hole FTL engine
  URL:=https://pi-hole.net/
  DEPENDS:=pihole +uci +libuci +libubus +libnettle \
	+libtre +libidn2 \
	+pihole_FTL_ipset:kmod-ipt-ipset \
	+pihole_FTL_conntrack:libnetfilter-conntrack \
	+pihole_FTL_readline:libreadline \
	+pihole_FTL_nftset:nftables-json \
<<<<<<< HEAD
	+pihole_FTL_shared_cjson:+cJSON \
	+pihole_FTL_shared_sqlite:+libsqlite3 +sqlite3-cli \
	+pihole_FTL_tls_mbedtls:libmbedtls \
	+pihole_FTL_tls_openssl:libopenssl
=======
	+pihole_FTL_shared_lua:+liblua5.3 +lua5.3 +luac5.3 \
	+pihole_FTL_shared_sqlite:+libsqlite3 +sqlite3-cli \
	+pihole_FTL_idn2:libidn2 \
	+!pihole_FTL_idn2:libidn
>>>>>>> e178876cd363c51946e0b821aba2be2344439299
  CONFLICTS:=dnsmasq
  USERID:=pihole=454:pihole=454
endef

define Package/pihole-FTL/description
  FTLDNS™ (pihole-FTL) provides an interactive API and also generates statistics for Pi-hole®'s Web interface.
endef

define Package/pihole-FTL/conffiles
/etc/config/pihole
/etc/dnsmasq.conf
endef

define Package/pihole-FTL/config
menu "pihole-FTL Compile Configuration"
	if PACKAGE_pihole-FTL
		config pihole_FTL_ipset
			bool "Build with IPset support."
			default y
		config pihole_FTL_nftset
			bool "Build with NFTables support."
			default n
		config pihole_FTL_conntrack
			bool "Build with Conntrack support."
			default n
		config pihole_FTL_shared_sqlite
			bool "Use system library sqlite3."
			default n
		config pihole_FTL_shared_cjson
			bool "Use system library cJSON."
			default n
		config pihole_FTL_tls_mbedtls
			bool "Build with MbedTLS TLS."
			default n
		config pihole_FTL_tls_openssl
			bool "Build with OpenSSL TLS."
			default y
		config pihole_FTL_build_doc
			bool "Build with Documentation API."
			default n
		config pihole_FTL_readline
			bool "Build with Readline support."
			depends on !pihole_FTL_shared_sqlite
			help
			  Enable Readline support for pihole-FTL sqlite3-cli and lua
			default y
	endif
endmenu
endef

define Package/pihole-FTL/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/pihole-FTL $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(LN) ../bin/pihole-FTL $(1)/usr/sbin/dnsmasq
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/dnsmasq.conf $(1)/etc/dnsmasq.conf
	$(INSTALL_DIR) $(1)/etc/dnsmasq.d
	$(INSTALL_DIR) $(1)/etc/pihole
	$(INSTALL_DATA) ./files/adlists.list $(1)/etc/pihole/
	$(INSTALL_DATA) ./files/macvendor.db $(1)/etc/pihole/
	$(INSTALL_DATA) ./files/whitelist.txt $(1)/etc/pihole/
	$(INSTALL_DIR) $(1)/etc/capabilities
	$(INSTALL_DATA) ./files/pihole-FTL.json $(1)/etc/capabilities
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/pihole-FTL.init $(1)/etc/init.d/pihole-FTL
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/pihole.config $(1)/etc/config/pihole
	$(INSTALL_DIR) $(1)/etc/hotplug.d/dhcp
	$(INSTALL_DIR) $(1)/etc/hotplug.d/neigh
	$(INSTALL_DIR) $(1)/etc/hotplug.d/ntp
	$(INSTALL_DIR) $(1)/etc/hotplug.d/tftp
	$(INSTALL_DATA) ./files/piholesec.hotplug $(1)/etc/hotplug.d/ntp/25-piholesec
	$(INSTALL_DIR) $(1)/usr/share/pihole
	$(INSTALL_DATA) ./files/rfc6761.conf $(1)/usr/share/pihole/
	$(INSTALL_DATA) ./files/dhcpbogushostname.conf $(1)/usr/share/pihole/
	$(INSTALL_DIR) $(1)/usr/lib/pihole
	$(INSTALL_BIN) ./files/dhcp-script.sh $(1)/usr/lib/pihole/dhcp-script.sh
	$(INSTALL_DIR) $(1)/usr/share/acl.d
	$(INSTALL_DATA) ./files/pihole_acl.json $(1)/usr/share/acl.d/
	$(INSTALL_DIR) $(1)/usr/share/pihole
	$(INSTALL_DATA) ./files/trust-anchors.conf $(1)/usr/share/pihole
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/50-dnsmasq-migrate-resolv-conf-auto.sh $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/50-dnsmasq-migrate-ipset.sh $(1)/etc/uci-defaults
endef

$(eval $(call BuildPackage,pihole-FTL))
