DEBIAN_DIST=experimental
HSN2_COMPONENT=cuckoo
HSN2_VER=2

PKG=hsn2-$(HSN2_COMPONENT)_$(HSN2_VER)-$(BUILD_NUMBER)_all
package: clean
	mkdir -p $(PKG)/opt/hsn2/cuckoo
	mkdir -p $(PKG)/etc/init.d
	mkdir -p $(PKG)/DEBIAN
	cp *.py $(PKG)/opt/hsn2/cuckoo/
	cp -rf cuckoo $(PKG)/opt/hsn2/cuckoo/cuckoo
	rm -rf `find $(PKG)/opt/hsn2/cuckoo/cuckoo -type d -name .svn`
	cp debian/initd $(PKG)/etc/init.d/hsn2-cuckoo
	cp debian/postrm $(PKG)/DEBIAN
	chmod 0775 $(PKG)/DEBIAN/postrm
	cp debian/control $(PKG)/DEBIAN
	sed -i "s/{VER}/${HSN2_VER}-${BUILD_NUMBER}/" $(PKG)/DEBIAN/control
	sed -i "s/{DEBIAN_DIST}/${DEBIAN_DIST}/" $(PKG)/DEBIAN/control
	fakeroot dpkg -b $(PKG)
	
clean:
	rm -rf $(PKG)
	rm -rf $(PKG).deb