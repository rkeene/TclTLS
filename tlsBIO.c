/*
 * Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 *
 * Provides BIO layer to interface openssl to Tcl.
 */

#include "tlsInt.h"

/*
 * Forward declarations
 */

static int BioWrite	_ANSI_ARGS_ ((BIO *h, CONST char *buf, int num));
static int BioRead	_ANSI_ARGS_ ((BIO *h, char *buf, int num));
static int BioPuts	_ANSI_ARGS_ ((BIO *h, CONST char *str));
static long BioCtrl	_ANSI_ARGS_ ((BIO *h, int cmd, long arg1, void *ptr));
static int BioNew	_ANSI_ARGS_ ((BIO *h));
static int BioFree	_ANSI_ARGS_ ((BIO *h));

BIO *
BIO_new_tcl(statePtr, flags)
    State *statePtr;
    int flags;
{
    BIO *bio;
    static BIO_METHOD BioMethods = {
        .type = BIO_TYPE_TCL,
	.name = "tcl",
        .bwrite = BioWrite,
        .bread = BioRead,
        .bputs = BioPuts,
        .ctrl = BioCtrl,
        .create = BioNew,
        .destroy = BioFree,
    };

    bio			= BIO_new(&BioMethods);
    bio->ptr		= (char*)statePtr;
    bio->init		= 1;
    bio->shutdown	= flags;

    return bio;
}

static int
BioWrite (bio, buf, bufLen)
    BIO *bio;
    CONST char *buf;
    int bufLen;
{
    Tcl_Channel chan = Tls_GetParent((State*)(bio->ptr));
    int ret;

    dprintf("BioWrite(%p, <buf>, %d) [%p]",
	    (void *) bio, bufLen, (void *) chan);

    if (channelTypeVersion == TLS_CHANNEL_VERSION_2) {
	ret = Tcl_WriteRaw(chan, buf, bufLen);
    } else {
	ret = Tcl_Write(chan, buf, bufLen);
    }

    dprintf("[%p] BioWrite(%d) -> %d [%d.%d]",
	    (void *) chan, bufLen, ret, Tcl_Eof(chan), Tcl_GetErrno());

    BIO_clear_flags(bio, BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY);

    if (ret == 0) {
	if (!Tcl_Eof(chan)) {
	    BIO_set_retry_write(bio);
	    ret = -1;
	}
    }
    if (BIO_should_read(bio)) {
	BIO_set_retry_read(bio);
    }
    return ret;
}

static int
BioRead (bio, buf, bufLen)
    BIO *bio;
    char *buf;
    int bufLen;
{
    Tcl_Channel chan = Tls_GetParent((State*)bio->ptr);
    int ret = 0;
    int tclEofChan;

    dprintf("BioRead(%p, <buf>, %d) [%p]", (void *) bio, bufLen, (void *) chan);

    if (buf == NULL) return 0;

    if (channelTypeVersion == TLS_CHANNEL_VERSION_2) {
	ret = Tcl_ReadRaw(chan, buf, bufLen);
    } else {
	ret = Tcl_Read(chan, buf, bufLen);
    }

    tclEofChan = Tcl_Eof(chan);

    dprintf("[%p] BioRead(%d) -> %d [tclEof=%d; tclErrno=%d]",
	    (void *) chan, bufLen, ret, tclEofChan, Tcl_GetErrno());

    BIO_clear_flags(bio, BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY);

    if (ret == 0) {
	if (!tclEofChan) {
            dprintf("Got 0 from Tcl_Read or Tcl_ReadRaw, and EOF is set -- ret == -1 now");
	    BIO_set_retry_read(bio);
	    ret = -1;
	}
    }
    if (BIO_should_write(bio)) {
	BIO_set_retry_write(bio);
    }

    dprintf("BioRead(%p, <buf>, %d) [%p] returning %i", (void *) bio, bufLen, (void *) chan, ret);

    return ret;
}

static int
BioPuts	(bio, str)
    BIO *bio;
    CONST char *str;
{
    return BioWrite(bio, str, (int) strlen(str));
}

static long
BioCtrl	(bio, cmd, num, ptr)
    BIO *bio;
    int cmd;
    long num;
    void *ptr;
{
    Tcl_Channel chan = Tls_GetParent((State*)bio->ptr);
    long ret = 1;
    int *ip;

    dprintf("BioCtrl(%p, 0x%x, 0x%x, %p)",
	    (void *) bio, (unsigned int) cmd, (unsigned int) num,
	    (void *) ptr);

    switch (cmd) {
    case BIO_CTRL_RESET:
	num = 0;
    case BIO_C_FILE_SEEK:
    case BIO_C_FILE_TELL:
	ret = 0;
	break;
    case BIO_CTRL_INFO:
	ret = 1;
	break;
    case BIO_C_SET_FD:
	BioFree(bio);
	/* Sets State* */
	bio->ptr	= *((char **)ptr);
	bio->shutdown	= (int)num;
	bio->init	= 1;
	break;
    case BIO_C_GET_FD:
	if (bio->init) {
	    ip = (int *)ptr;
	    if (ip != NULL) {
		*ip = bio->num;
	    }
	    ret = bio->num;
	} else {
	    ret = -1;
	}
	break;
    case BIO_CTRL_GET_CLOSE:
	ret = bio->shutdown;
	break;
    case BIO_CTRL_SET_CLOSE:
	bio->shutdown = (int)num;
	break;
    case BIO_CTRL_EOF:
	dprintf("BIO_CTRL_EOF");
	ret = Tcl_Eof(chan);
	break;
    case BIO_CTRL_PENDING:
	ret = (Tcl_InputBuffered(chan) ? 1 : 0);
	dprintf("BIO_CTRL_PENDING(%d)", (int) ret);
	break;
    case BIO_CTRL_WPENDING:
	ret = 0;
	break;
    case BIO_CTRL_DUP:
	break;
    case BIO_CTRL_FLUSH:
	dprintf("BIO_CTRL_FLUSH");
	if (channelTypeVersion == TLS_CHANNEL_VERSION_2) {
	    ret = ((Tcl_WriteRaw(chan, "", 0) >= 0) ? 1 : -1);
	} else {
	    ret = ((Tcl_Flush(chan) == TCL_OK) ? 1 : -1);
	}
	break;
    default:
	ret = 0;
	break;
    }
    return(ret);
}

static int
BioNew	(bio)
    BIO *bio;
{
    bio->init	= 0;
    bio->num	= 0;
    bio->ptr	= NULL;
    bio->flags	= 0;

    return 1;
}

static int
BioFree	(bio)
    BIO *bio;
{
    if (bio == NULL) {
	return 0;
    }

    if (bio->shutdown) {
	if (bio->init) {
	    /*shutdown(bio->num, 2) */
	    /*closesocket(bio->num) */
	}
	bio->init	= 0;
	bio->flags	= 0;
	bio->num	= 0;
    }
    return 1;
}
