build:
	mvn clean package

install:
	mvn clean package && onos-app localhost reinstall! org.onosproject.ifwd target/onos-app-ifwd-1.0-SNAPSHOT.oar
