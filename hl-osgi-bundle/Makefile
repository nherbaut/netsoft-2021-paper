ONOS_DEPLOY_PATH := "/tmp/onos-2.4.0/apache-karaf-4.2.8/deploy"

all: build deploy

build:
	mvn clean compile

deploy:
	ONOS_DEPLOY_PATH=$(ONOS_DEPLOY_PATH) mvn package

