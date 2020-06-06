all: build deploy
build:
	mvn package

deploy:
	onos-app localhost reinstall! org.onosproject.ifwd target/onos-app-ifwd-1.1-SNAPSHOT.oar
