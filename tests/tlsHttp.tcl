#
# Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
#
# $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tests/Attic/tlsHttp.tcl,v 1.2 2000/01/20 01:56:44 aborr Exp $
#
package require base64

set dir [file dirname [info script]]
cd $dir
source tls.tcl
package require http

#
# Initialize context
#
#tls::init -certfile client.pem -cafile server.pem -ssl2 1 -ssl3 1 -tls1 0 ;#-cipher RC4-MD5
tls::init -cafile server.pem 
#
# Register with http module
#
http::register https 443 [list ::tls::socket -require 1]

set user novadigm\\matt
set pass sensus

set auth [Base64_Encode "${user}:$pass"]
set hdrs [list Authorization [list Basic $auth]]
#set hdrs {}

set url http://localhost:3466/
set url https://intranet.novadigm.com/
set url https://localhost/
set url https://developer.netscape.com/

set tok [http::geturl $url -headers $hdrs]

parray $tok
exit
