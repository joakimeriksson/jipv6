This is a host application that make the Sun SPOT base station
a IPv6 router for connected Sun SPOTs.

First create a build.properties file based on the one below
but add your host (amsterdam.freenet6.net) user and password.
Go to go6.net

ant host-compile
ant host-run

---- build.properties ---
# Properties file for a Sun Spot Host Application
#
# build.properties
#
# This file is the default location for user properties that over-ride the
# defaults in ${sunspot.home}/default.properties.  See that file for a full
# listing of the properties that may be set.  This file is minimal and
# contains only those properties that a user would generally need to set
# right away.
#

#
# the host application's main class and arguments
# (for building as a host application - NOT for building
# a MIDlet to be deployed onto a SunSpot)
#
main.class=se.sics.sunspot.IPv6Router
main.args=<HOST> <USER> <PASS>
user.classpath=
---
