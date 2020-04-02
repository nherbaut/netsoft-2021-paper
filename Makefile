intent:  hl-bundle-build hl-bundle-deploy intent-build intent-deploy
reactive: hl-bundle-build hl-bundle-deploy reactive-build reactive-deploy


hl-bundle-build:
	$(MAKE) build -C hl-osgi-bundle
intent-build:
	$(MAKE) builc -C ifwd
reactive-build:
	$(MAKE) build -C fwd2


hl-bundle-deploy:
	$(MAKE) deploy -C hl-osgi-bundle
intent-deploy:
	$(MAKE) deploy -C ifwd
reactive-deploy:
	$(MAKE) deploy -C fwd2


