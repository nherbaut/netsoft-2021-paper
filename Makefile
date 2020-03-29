all: hl-bundle intent


hl-bundle:
	$(MAKE) all -C hl-osgi-bundle
intent:
	$(MAKE) all -C ifwd
