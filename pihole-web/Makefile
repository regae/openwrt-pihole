include $(TOPDIR)/rules.mk

PKG_NAME:=pihole-web
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/pi-hole/web
PKG_SOURCE_VERSION:=2889bb5a0a555a7fe12c03536058708bfdad7a88
PKG_MIRROR_HASH:=f5f88c8e8ce7a13d2b87c1749c0332d3b0a10ae00efe6a541e824e72b359d2ec
PKG_VERSION:=6.0-$(call version_abbrev,$(PKG_SOURCE_VERSION))

PKG_LICENSE:=EUPL
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
define Package/pihole-web
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Pi-hole Dashboard for stats and more
  URL:=https://pi-hole.net/
  DEPENDS:=pihole
endef

define Package/pihole-web/description
  Pi-hole®'s Web interface (based off of AdminLTE) provides a central location to manage your Pi-hole and review the statistics generated by FTLDNS™.
endef

define Build/Compile
endef

define Package/pihole-web/install
	$(INSTALL_DIR) $(1)/usr/lib/pihole/admin
	$(CP) -r $(PKG_BUILD_DIR)/{img,scripts,style,*.lp} $(1)/usr/lib/pihole/admin
endef

define Package/pihole-web/postinst
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	sed -i '/doc_root/ s/^;*/;/' /etc/php.ini
fi
exit 0
endef

override CONFIG_AUTOREMOVE=

$(eval $(call BuildPackage,pihole-web))
