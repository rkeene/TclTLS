/*
 * Copyright (C) 1997-2000 Sensus Consulting Ltd.
 * Matt Newman <matt@sensus.org>
 *
 * $Header: /home/rkeene/tmp/cvs2fossil/../tcltls/tls/tls/tlsX509.c,v 1.2 2000/01/20 01:53:14 aborr Exp $
 */
#include "tlsInt.h"

/*
 * ASN1_UTCTIME_tostr --
 */
static char *
ASN1_UTCTIME_tostr(ASN1_UTCTIME *tm)
{
    static char bp[128];
    char *v;
    int gmt=0;
    static char *mon[12]={
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"};
    int i;
    int y=0,M=0,d=0,h=0,m=0,s=0;
    
    i=tm->length;
    v=(char *)tm->data;
    
    if (i < 10) goto err;
    if (v[i-1] == 'Z') gmt=1;
    for (i=0; i<10; i++)
        if ((v[i] > '9') || (v[i] < '0')) goto err;
    y= (v[0]-'0')*10+(v[1]-'0');
    if (y < 70) y+=100;
    M= (v[2]-'0')*10+(v[3]-'0');
    if ((M > 12) || (M < 1)) goto err;
    d= (v[4]-'0')*10+(v[5]-'0');
    h= (v[6]-'0')*10+(v[7]-'0');
    m=  (v[8]-'0')*10+(v[9]-'0');
    if (	(v[10] >= '0') && (v[10] <= '9') &&
		(v[11] >= '0') && (v[11] <= '9'))
        s=  (v[10]-'0')*10+(v[11]-'0');
    
    sprintf(bp,"%s %2d %02d:%02d:%02d %d%s",
                   mon[M-1],d,h,m,s,y+1900,(gmt)?" GMT":"");
    return bp;
 err:
    return "Bad time value";
}

/*
 *------------------------------------------------------*
 *
 *	Tls_NewX509Obj --
 *
 *	------------------------------------------------*
 *	Converts a X509 certificate into a Tcl_Obj
 *	------------------------------------------------*
 *
 *	Sideeffects:
 *		None
 *
 *	Result:
 *		A Tcl List Object representing the provided
 *		X509 certificate.
 *
 *------------------------------------------------------*
 */

Tcl_Obj*
Tls_NewX509Obj( interp, cert)
    Tcl_Interp *interp;
    X509 *cert;
{
    Tcl_Obj *certPtr = Tcl_NewListObj( 0, NULL);
    int serial;
    char subject[BUFSIZ];
    char issuer[BUFSIZ];
    char notBefore[BUFSIZ];
    char notAfter[BUFSIZ];

    serial = ASN1_INTEGER_get(X509_get_serialNumber(cert));
    X509_NAME_oneline(X509_get_subject_name(cert),subject,sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(cert),issuer,sizeof(issuer));

    strcpy( notBefore, ASN1_UTCTIME_tostr( X509_get_notBefore(cert) ));
    strcpy( notAfter, ASN1_UTCTIME_tostr( X509_get_notAfter(cert) ));

    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( "subject", -1) );
    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( subject, -1) );

    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( "issuer", -1) );
    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( issuer, -1) );

    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( "notBefore", -1) );
    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( notBefore, -1) );

    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( "notAfter", -1) );
    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( notAfter, -1) );

    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewStringObj( "serial", -1) );
    Tcl_ListObjAppendElement( interp, certPtr,
	    Tcl_NewIntObj( serial) );

    return certPtr;
}
