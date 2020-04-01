all: build install
build:
	mvn package

install:
	onos-app localhost reinstall! org.onosproject.ifwd target/onos-app-ifwd-1.1-SNAPSHOT.oar
