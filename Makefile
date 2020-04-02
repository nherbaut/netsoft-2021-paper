all: hl-bundle intent reactive


hl-bundle:
	$(MAKE) all -C hl-osgi-bundle
intent:
	$(MAKE) all -C ifwd
reactive:
	$(MAKE) all -c fwd2
