include $(TOPDIR)/rules.mk

PKG_NAME:=pihole
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/pi-hole/pi-hole
PKG_SOURCE_VERSION:=159be01e0e5252bfa6837123f09c3c723e6fb610
PKG_MIRROR_HASH:=9d44c5dce1bae8b43f9d2589dd6fad4545dfe9395226b76e25c6e642c3cf336a
PKG_VERSION:=6.0-$(call version_abbrev,$(PKG_SOURCE_VERSION))

PKG_LICENSE:=EUPL
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/pihole
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A black hole for Internet advertisements
  URL:=https://pi-hole.net/
  DEPENDS:=+bash +bind-dig +bind-host +ca-bundle +coreutils +coreutils-tr +coreutils-sha1sum +curl +grep +idn2 +sed
endef

define Package/pihole/description
  The Pi-hole® is a DNS sinkhole that protects your devices from unwanted content, without installing any client-side software.
endef

define Build/Compile
endef

define Package/pihole/install
	$(INSTALL_DIR) $(1)/usr/bin
ifdef CONFIG_USE_GLIBC
	$(INSTALL_BIN) $(TOOLCHAIN_DIR)/bin/getent $(1)/usr/bin/
endif
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pihole $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib/pihole
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/gravity.sh $(1)/usr/lib/pihole/
	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/api.sh $(1)/usr/lib/pihole/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/version.sh $(1)/usr/lib/pihole/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/piholeLogFlush.sh $(1)/usr/lib/pihole/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/list.sh $(1)/usr/lib/pihole/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/query.sh $(1)/usr/lib/pihole/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/utils.sh $(1)/usr/lib/pihole/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/pihole-reenable.sh $(1)/usr/lib/pihole/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/piholeARPTable.sh $(1)/usr/lib/pihole/

	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Scripts/COL_TABLE $(1)/usr/lib/pihole/

	$(INSTALL_DIR) $(1)/usr/lib/pihole/Templates
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Templates/gravity.db.sql $(1)/usr/lib/pihole/Templates/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/advanced/Templates/gravity_copy.sql $(1)/usr/lib/pihole/Templates/

	$(CP) -pr $(PKG_BUILD_DIR)/advanced/Scripts/database_migration $(1)/usr/lib/pihole/
endef

define Package/pihole/postinst
#!/usr/bin/env bash
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	echo "Installing cron rules"
	grep -q "pihole updateGravity" /etc/crontabs/root 2> /dev/null ||
		echo "$$((1 + RANDOM % 58)) $$((3 + RANDOM % 2)) * * 6 /usr/bin/pihole updateGravity" >> /etc/crontabs/root
	
	echo "Restarting cron"
	/etc/init.d/cron restart
fi
exit 0
endef

define Package/pihole/prerm
#!/usr/bin/env bash
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	echo "Removing cron rules"
	grep -q "pihole updateGravity" /etc/crontabs/root 2> /dev/null &&
		sed -i "/pihole updateGravity/d" /etc/crontabs/root

	echo "Restarting cron"
	/etc/init.d/cron restart
fi
exit 0
endef

override CONFIG_AUTOREMOVE=

$(eval $(call BuildPackage,pihole))
