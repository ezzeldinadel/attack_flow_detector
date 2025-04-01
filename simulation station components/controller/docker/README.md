# OpenDaylight Docker

## Introduction

Docker container for OpenDaylight (ODL) SDN controller with the 
[Virtual Tenant Network (VTN) plugin](https://docs.opendaylight.org/en/stable-fluorine/user-guide/virtual-tenant-network-(vtn).html) 
installed.

## What is ODL?

OpenDaylight is an open-source SDN controller developed by The Linux Foundation. An 
SDN controller is the module holding a global view of the network and providing
all SDN-enabled switches in the network with the instructions on how to relay
the packets through the network.

OpenDaylight allows for installing and removing feature such as l2 switching, web GUI, OpenFlow support, etc.
in a modular fashion.

## What is VTN?

VTN (Virtual Tenant Networks) is a robust framework inside ODL for defining logical
virtual networks on top of the underlying network infrastructure. This allows for
a strong and flexible slicing of the network and providing isolation by only describing
the kind of virtualization needed. VTN takes care of generating the proper OpenFlow 
instructions and installing it on the network infrastructure.

For more information, check out the official [docs](https://docs.opendaylight.org/en/stable-fluorine/user-guide/virtual-tenant-network-(vtn).html).

## Why Docker?

Using a Dockerized controller can be very useful in networks that are dynamically deployed. 
For instance, virtual networks themselves can have separate controllers. This can also
make experiments with Mininet and other simulators far easier.

Moreover, setting up VTN is far from straightforward. The container has the VTN requirements
preinstalled.

## Version

OpenDaylight **0.6.2-Carbon**

Ubuntu **16.04.6**

Java **OpenJDK 1.8**


## License
MIT 
