#
# Copyright (C) 1997-1999 Matt Newman <matt@novadigm.com>
#
# $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tests/Attic/tls.tcl,v 1.1.1.1 2000/01/19 22:10:59 aborr Exp $
#
set dir [file dirname [info script]]
regsub {\.} [info tclversion] {} vshort
if {$tcl_platform(platform) == "windows"} {
    if {[info exists tcl_platform(debug)]} {
	load $dir/../win/Debug$vshort/tls.dll
    } else {
	load $dir/../win/Release$vshort/tls.dll
    }
} else {
    load [glob $dir/../unix/libtls*]
}

proc bgerror {err} {
    global errorInfo
    puts stderr "BG Error: $errorInfo"
}

source $dir/../library/tls.tcl
set tls::debug 2

