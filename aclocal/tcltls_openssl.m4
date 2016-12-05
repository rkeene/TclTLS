AC_DEFUN([TCLTLS_SSL_OPENSSL], [
	dnl Use pkg-config to find the libraries
	TCLTLS_SSL_LIBS="`"${PKGCONFIG}" openssl --libs`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	TCLTLS_SSL_CFLAGS="`"${PKGCONFIG}" openssl --cflags-only-other`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])
	TCLTLS_SSL_CPPFLAGS="`"${PKGCONFIG}" openssl --cflags-only-I`" || AC_MSG_ERROR([Unable to get OpenSSL Configuration])

	dnl Save compile-altering variables we are changing
	SAVE_LIBS="${LIBS}"
	SAVE_CFLAGS="${CFLAGS}"
	SAVE_CPPFLAGS="${CPPFLAGS}"

	dnl Update compile-altering variables to include the OpenSSL libraries
	LIBS="${SAVE_LIBS} ${TCLTLS_SSL_LIBS}"
	CFLAGS="${SAVE_CFLAGS} ${TCLTLS_SSL_CFLAGS}"
	CPPFLAGS="${SAVE_CPPFLAGS} ${TCLTLS_SSL_CPPFLAGS}"

	dnl Verify that basic functionality is there
	AC_LANG_PUSH(C)
	AC_MSG_CHECKING([if a basic OpenSSL program works])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <openssl/ssl.h>
#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
# include <openssl/conf.h>
#endif
		], [
  (void)SSL_library_init();
  SSL_load_error_strings();
  OPENSSL_config(NULL);
		])], [
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Unable to compile a basic program using OpenSSL])
	])
	AC_LANG_POP([C])

	dnl Determine if SSLv2 is supported
	AC_CHECK_FUNC(SSLv2_method,, [
		AC_DEFINE(NO_SSL2, [1], [Define this to disable SSLv2 in OpenSSL support])
	])

	dnl Determine if SSLv3 is supported
	AC_CHECK_FUNC(SSLv3_method,, [
		AC_DEFINE(NO_SSL3, [1], [Define this to disable SSLv3 in OpenSSL support])
	])

	dnl Determine if TLSv1.0 is supported
	AC_CHECK_FUNC(TLSv1_method,, [
		AC_DEFINE(NO_TLS1, [1], [Define this to disable TLSv1.0 in OpenSSL support])
	])

	dnl Determine if TLSv1.1 is supported
	AC_CHECK_FUNC(TLSv1_1_method,, [
		AC_DEFINE(NO_TLS1_1, [1], [Define this to disable TLSv1.1 in OpenSSL support])
	])

	dnl Determine if TLSv1.2 is supported
	AC_CHECK_FUNC(TLSv1_2_method,, [
		AC_DEFINE(NO_TLS1_2, [1], [Define this to disable TLSv1.2 in OpenSSL support])
	])

	dnl Restore compile-altering variables
	LIBS="${SAVE_LIBS}"
	CFLAGS="${SAVE_CFLAGS}"
	CPPFLAGS="${SAVE_CPPFLAGS}"
])
