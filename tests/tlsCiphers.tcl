#
# Copyright (C) 1997-1999 Matt Newman <matt@novadigm.com>
#
# $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tests/Attic/tlsCiphers.tcl,v 1.1.1.1 2000/01/19 22:10:59 aborr Exp $
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
