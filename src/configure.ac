AC_INIT(LittleBlackBox, 0.1.4)

AC_PROG_CC
AC_LANG(C)

CFLAGS="-Wall $CFLAGS"

dnl These libraries are required for both static and shared builds
AC_CHECK_LIB(pthread, pthread_create, [], [echo "error: pthread library not found!"; exit -1])
AC_CHECK_LIB(rt, clock_gettime,       [], [echo "error: rt library not found!"; exit -1])

AC_CHECK_HEADER(sqlite3.h,     [], [echo "error: sqlite3.h not found!"; exit -1])
AC_CHECK_HEADER(openssl/ssl.h, [], [echo "error: openssl/ssl.h not found!"; exit -1])
AC_CHECK_HEADER(pcap.h,        [], [echo "error: pcap.h not found!"; exit -1])
AC_CHECK_HEADER(curl/curl.h,   [], [echo "error: curl/curl.h not found!"; exit -1])

AC_CHECK_LIB(sqlite3, sqlite3_open, [], [echo "error: sqlite3 library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_open_live,  [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(ssl, SSL_library_init, [], [echo "error: ssl library not found!"; exit -1])
AC_CHECK_LIB(crypto, main,          [], [echo "error: crypto library not found!"; exit -1])
AC_CHECK_LIB(curl, curl_easy_init,  [], [echo "error: curl library not found!"; exit -1])

dnl BSD doesn't like the -ldl linker option
if uname -s | grep -qi "BSD"
then
	LDL=
else
	LDL=-ldl
fi

AC_SUBST(LDL, $LDL)

cp confdefs.h config.h

AC_OUTPUT(Makefile)
