#
# Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
#
# $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tests/Attic/tlsBlocking.tcl,v 1.2 2000/01/20 01:56:26 aborr Exp $
#

set dir [file dirname [info script]]
cd $dir
source tls.tcl

proc bgerror {msg} {tclLog "BG: $msg"}

array set opts {
    -port 1234
    -host localhost
}
array set opts $argv
#
# Initialize Context
#
# Comment out next line for non-RSA testing
#tls::init -cafile server.pem -certfile client.pem
#tls::init
#
# Create socket and import
#
set chan [tls::socket -require 0 $opts(-host) $opts(-port)]
tls::handshake $chan

set max 10
#set max 100
#set max 3
for {set i 0} {$i < $max} {incr i} {
    puts $chan line$i
    flush $chan
    puts stdout [gets $chan]
}
close $chan
