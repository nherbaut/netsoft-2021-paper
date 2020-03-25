intent:  hl-bundle-build hl-bundle-deploy intent-build intent-deploy
reactive: hl-bundle-build hl-bundle-deploy reactive-build reactive-deploy


hl-bundle-build:
	$(MAKE) build -C hl-osgi-bundle
intent-build:
	$(MAKE) build -C scoi
reactive-build:
	$(MAKE) build -C sco


hl-bundle-deploy:
	$(MAKE) deploy -C hl-osgi-bundle
intent-deploy:
	$(MAKE) deploy -C scoi
reactive-deploy:
	$(MAKE) deploy -C sco


