# What is this project? #

This repository contains sources for our submission to the BRAINS conference

## What's inside ? ##

* conformance-checker  : a custom program that uses logs from the Management Plane and the Control plane to report on the actual deployment of of business rules on the SDN forwading devices
* fault-injector  : a custom program that triggers Management plane-based reconfiguration 
* hl-osgi-bundle : a middleware integrating an Hyperledger Fabric client in an OSGI bundle deployable on ONOS SDN Controller
* result_analysis : a tool to generate graphs and results for the paper
* sco  : an SDN app that performs security and connectivity objectives of the Management Plane through flow-based techniques
* scoi  : an SDN app that performs security and connectivity objectives of the Management Place through Intent-based networking
* security-policy-monitor : a custom program that update management plane configuration when a new fault is detected
* testbed : a mininet modular testbed

## How to use it? ##

See the Makefiles at the root and in each sub-project

