/*
 * Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 *
 * Provides BIO layer to interface openssl to Tcl.
 */

#include "tlsInt.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define BIO_get_data(bio)                ((bio)->ptr)
#define BIO_get_init(bio)                ((bio)->init)
#define BIO_get_shutdown(bio)            ((bio)->shutdown)
#define BIO_set_data(bio, val)           (bio)->ptr = (val)
#define BIO_set_init(bio, val)           (bio)->init = (val)
#define BIO_set_shutdown(bio, val)       (bio)->shutdown = (val)

/* XXX: This assumes the variable being assigned to is BioMethods */
#define BIO_meth_new(type_, name_)       (BIO_METHOD *)Tcl_Alloc(sizeof(BIO_METHOD)); \
                                         memset(BioMethods, 0, sizeof(BIO_METHOD)); \
                                         BioMethods->type = type_; \
                                         BioMethods->name = name_;
#define BIO_meth_set_write(bio, val)     (bio)->bwrite = val;
#define BIO_meth_set_read(bio, val)      (bio)->bread = val;
#define BIO_meth_set_puts(bio, val)      (bio)->bputs = val;
#define BIO_meth_set_ctrl(bio, val)      (bio)->ctrl = val;
#define BIO_meth_set_create(bio, val)    (bio)->create = val;
#define BIO_meth_set_destroy(bio, val)   (bio)->destroy = val;
#endif

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
    static BIO_METHOD *BioMethods = NULL;

    if (BioMethods == NULL) {
        BioMethods = BIO_meth_new(BIO_TYPE_TCL, "tcl");
        BIO_meth_set_write(BioMethods, BioWrite);
        BIO_meth_set_read(BioMethods, BioRead);
        BIO_meth_set_puts(BioMethods, BioPuts);
        BIO_meth_set_ctrl(BioMethods, BioCtrl);
        BIO_meth_set_create(BioMethods, BioNew);
        BIO_meth_set_destroy(BioMethods, BioFree);
    }

    bio = BIO_new(BioMethods);

    BIO_set_data(bio, statePtr);
    BIO_set_init(bio, 1);
    BIO_set_shutdown(bio, flags);

    return bio;
}

static int
BioWrite (bio, buf, bufLen)
    BIO *bio;
    CONST char *buf;
    int bufLen;
{
    Tcl_Channel chan = Tls_GetParent((State*)BIO_get_data(bio));
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
    Tcl_Channel chan = Tls_GetParent((State*)BIO_get_data(bio));
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
            dprintf("Got 0 from Tcl_Read or Tcl_ReadRaw, and EOF is not set -- ret == -1 now");
	    BIO_set_retry_read(bio);
	    ret = -1;
	} else {
            dprintf("Got 0 from Tcl_Read or Tcl_ReadRaw, and EOF is set");
        }
    } else {
        dprintf("Got non-zero from Tcl_Read or Tcl_ReadRaw == ret == %i", ret);
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
    Tcl_Channel chan = Tls_GetParent((State*)BIO_get_data(bio));
    long ret = 1;

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
        dprintf("Unsupported call: BIO_C_SET_FD");
        ret = -1;
        break;
    case BIO_C_GET_FD:
        dprintf("Unsupported call: BIO_C_GET_FD");
        ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
	ret = BIO_get_shutdown(bio);
	break;
    case BIO_CTRL_SET_CLOSE:
	BIO_set_shutdown(bio, num);
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
        dprintf("BIO_CTRL_FLUSH returning value %li", ret);
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
    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    BIO_clear_flags(bio, -1);

    return 1;
}

static int
BioFree	(bio)
    BIO *bio;
{
    if (bio == NULL) {
	return 0;
    }
    if (BIO_get_shutdown(bio)) {
	if (BIO_get_init(bio)) {
	    /*shutdown(bio->num, 2) */
	    /*closesocket(bio->num) */
	}
        BIO_set_init(bio, 0);
        BIO_clear_flags(bio, -1);
    }
    return 1;
}
