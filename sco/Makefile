all: build deploy

build:
	mvn package

deploy:
	onos-app localhost reinstall! org.onosproject.fwd2 target/onos-app-fwd2-1.0-SNAPSHOT.oar
