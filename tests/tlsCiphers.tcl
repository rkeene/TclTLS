#
# Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
#
# $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tests/Attic/tlsCiphers.tcl,v 1.2 2000/01/20 01:56:36 aborr Exp $
#

set dir [file dirname [info script]]
cd $dir
source tls.tcl

if {[llength $argv] == 0} {
    puts stderr "Usage: ciphers protocol ?verbose?"
    exit 1
}
puts [join [eval tls::ciphers $argv] \n]
exit 0
