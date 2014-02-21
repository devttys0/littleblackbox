AC_INIT(LittleBlackBox, 0.1.3)

AC_ARG_ENABLE(static, [  --enable-static         enable static compilation ], STATIC=y, STATIC=n)

OPENSSL=openssl
LIBPCAP=libpcap
SQLITE=sqlite
LIBCURL=libcurl

AC_PROG_CC
AC_LANG(C)

CFLAGS="-Wall $CFLAGS"

dnl These libraries are required for both static and shared builds
AC_CHECK_LIB(pthread, pthread_create, [], [echo "error: pthread library not found!"; exit -1])
AC_CHECK_LIB(rt, clock_gettime,       [], [echo "error: rt library not found!"; exit -1])

dnl If not performing a static build, the host system must have these headers and libs installed
if test $STATIC = n
then
	AC_CHECK_HEADER(sqlite3.h,     [], [echo "error: sqlite3.h not found!"; exit -1])
	AC_CHECK_HEADER(openssl/ssl.h, [], [echo "error: openssl/ssl.h not found!"; exit -1])
	AC_CHECK_HEADER(pcap.h,        [], [echo "error: pcap.h not found!"; exit -1])
	AC_CHECK_HEADER(curl/curl.h,   [], [echo "error: curl/curl.h not found!"; exit -1])

	AC_CHECK_LIB(sqlite3, sqlite3_open, [], [echo "error: sqlite3 library not found!"; exit -1])
	AC_CHECK_LIB(pcap, pcap_open_live,  [], [echo "error: pcap library not found!"; exit -1])
	AC_CHECK_LIB(ssl, SSL_library_init, [], [echo "error: ssl library not found!"; exit -1])
	AC_CHECK_LIB(crypto, main,          [], [echo "error: crypto library not found!"; exit -1])
	AC_CHECK_LIB(curl, curl_easy_init,  [], [echo "error: curl library not found!"; exit -1])

	AC_SUBST(INC, "")
        AC_SUBST(LIB, "")
        AC_SUBST(BUILD_LIBS, n)
dnl Else if we are performing a static build, all the libraries will be built in a local directory
else
	CFLAGS="-static $CFLAGS"
	AC_SUBST(INC, "-I./$OPENSSL/include -I./$LIBPCAP/include -I./$SQLITE/include -I./$LIBCURL/include")
	AC_SUBST(LIB, "-L./$OPENSSL/lib -L./$LIBPCAP/lib -L./$SQLITE/lib -L./$LIBCURL/lib")
	AC_SUBST(BUILD_LIBS, y)
fi

dnl BSD doesn't like the -ldl linker option
if uname -s | grep -qi "BSD"
then
	LDL=
else
	LDL=-ldl
fi

AC_SUBST(LDL, $LDL)
AC_SUBST(STATIC, $STATIC)
AC_SUBST(SQLITE, $SQLITE)
AC_SUBST(LIBCURL, $LIBCURL)
AC_SUBST(LIBPCAP, $LIBPCAP)
AC_SUBST(OPENSSL, $OPENSSL)

cp confdefs.h config.h

AC_OUTPUT(Makefile)
