
# packet-o-matic : modular network traffic processor
# Copyright (C) 2007 Guy Martin <gmsoft@tuxicoman.be>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA



#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([packet-o-matic], [svn], [gmsoft@tuxicoman.be])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_DEFUN([AC_PROG_CXX], [])
AC_PROG_LIBTOOL

# Checks for libraries.

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([arpa/inet.h fcntl.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# BSD specific header files
AC_CHECK_HEADERS([sys/endian.h])

# Linux specidic header files
AC_CHECK_HEADERS([mcheck.h endian.h])

# Check endianess
AC_C_BIGENDIAN

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero gettimeofday inet_ntoa memmove memset strerror])

# Try to find a good CFLAGS/LDFLAGS for pthreads
AC_CHECK_HEADERS(pthread.h, [], [AC_MSG_ERROR([pthread support required])])
CFLAGS="$CFLAGS -D_REENTRANT"
checkpthread=yes

AC_MSG_CHECKING([for pthread_create with libc])
AC_TRY_LINK([], [pthread_create();], 
                [pthflag=yes; checkpthread=no], 
                [pthflag=no])
AC_MSG_RESULT($pthflag)

for flag in "pthreads" "pthread"; do
  if test "x$checkpthread" = "xyes"; then
    AC_MSG_CHECKING([for pthread_create with -$flag])
    OLDLDFLAGS="$LDFLAGS"
    LDFLAGS="-$flag $LDFLAGS"
    AC_TRY_LINK([], [pthread_create();], 
                    [pthflag=yes; checkpthread=no], 
                    [pthflag=no; LDFLAGS="$OLDLDFLAGS"])
    AC_MSG_RESULT($pthflag)
  fi
done

for lib in "c_r" "pthread"; do
  if test "x$checkpthread" = "xyes"; then
     case "x$LIBS" in
        *-l$lib*);;
        *) AC_CHECK_LIB($lib, pthread_create, [LIBS="$LIBS -l$lib"; checkpthread=no]) ;;
     esac
   fi
done

if test "x$checkpthread" = "xyes"; then
  AC_CHECK_FUNC(pthread_create, checkpthread=no)
  text "x$checkpthread" = "xyes" && AC_MSG_ERROR([pthread library required])
fi


LIB_DL=''
AC_CHECK_LIB([dl], [dlopen], [LIB_DL='-ldl'])
LIBS="$LIB_DL $LIBS"

AC_CHECK_LIB([nsl], [gethostbyname])
AC_CHECK_LIB([socket], [socket])



# Checks for packages.
PKG_CHECK_MODULES(libxml2, [libxml-2.0], [], [AC_MSG_ERROR([libxml2 is required to build this program])])
AC_SUBST(libxml2_CFLAGS)
AC_SUBST(libxml2_LIBS)

AC_CONFIG_FILES([Makefile
                 src/Makefile])

# #define LIB_DIR
LIB_DIR='${libdir}'
AC_SUBST(LIB_DIR)

# Check for PCAP
AC_CHECK_HEADERS([pcap.h pcap-bpf.h], [pcap_headers=yes], [pcap_headers=no])
AC_CHECK_LIB([pcap], [pcap_open_offline, pcap_open_dead, pcap_close, pcap_breakloop], [want_pcap=yes], [want_pcap=no])
if test "x$pcap_headers" = "xyes" -a "x$want_pcap" = "xyes"
then
	INPUT_OBJS="$INPUT_OBJS input_pcap.la"
	TARGET_OBJS="$TARGET_OBJS target_pcap.la target_inject.la target_tcpkill.la"
fi

# Check for Linux' raw socket iface
AC_CHECK_HEADERS([linux/socket.h netpacket/packet.h], [want_netpacket=yes], [want_netpacket=no])

if test "x$want_netpacket" = "xyes"
then
	AC_DEFINE(HAVE_LINUX_IP_SOCKET, , [Linux' raw socket iface])
fi

# Check for DVB
AC_CHECK_HEADERS([linux/dvb/dmx.h linux/dvb/frontend.h], [want_dvb=yes], [want_dvb=no])

if test "x$want_dvb" = "xyes"
then
	INPUT_OBJS="input_docsis.la $INPUT_OBJS"
fi

if test "x$INPUT_OBJS" = "x"
then
	AC_MSG_ERROR([No input could be compiled.])
fi

# Check for Linux' tun header
AC_CHECK_HEADERS([linux/if_tun.h], [want_tun=yes], [want_tun=no])
if test "x$want_tun" = "xyes"
then
	TARGET_OBJS="$TARGET_OBJS target_tap.la"
fi


# Check for xmlrpc-c

OLD_LIBS=[$LIBS]
AC_CHECK_HEADERS([xmlrpc-c/base.h xmlrpc-c/server.h xmlrpc-c/server_abyss.h], [xmlrpc_headers=yes], [xmlrpc_headers=no])
AC_CHECK_LIB([xmlrpc_util], [xmlrpc_millisecond_sleep], [LIB_XMLRPC_UTIL='-lxmlrpc_util'])
LIBS="$LIB_XMLRPC_UTIL $LIBS"
AC_CHECK_LIB([xmlrpc_abyss], [ServerRunConn2], [want_xmlrpc=$xmlrpc_headers], [want_xmlrpc=no])

AC_MSG_CHECKING([for xmlrpc-c-config])
XMLRPC_CONFIG=`which xmlrpc-c-config 2>/dev/null`
if [ test ! -x "${XMLRPC_CONFIG}" ]
then
	want_xmlrpc=no
fi
AC_MSG_RESULT($want_xmlrpc)

AM_CONDITIONAL([USE_XMLRPC], [test "x$want_xmlrpc" = "xyes"])

if test "x$want_xmlrpc" = "xyes"
then
	xmlrpc_LIBS="-lxmlrpc_server_abyss -lxmlrpc_server -lxmlrpc_abyss -lxmlrpc -lxmlrpc_util -lz -lm"
	xmlrpc_LIBS="${xmlrpc_LIBS} `xmlrpc-c-config abyss-server --libs`"
	AC_DEFINE(USE_XMLRPC, , [Compile XML-RPC interface])
fi
LIBS="$OLD_LIBS"

AC_SUBST(xmlrpc_SRC)
AC_SUBST(xmlrpc_LIBS)

# Check for PostgreSQL
AC_CHECK_HEADERS([libpq-fe.h], [want_postgres=yes], [want_postgres=no])
if test "x$want_postgres" = "xyes"
then
	DATASTORE_OBJS="$DATASTORE_OBJS datastore_postgres.la"
fi

# Check for Sqlite3
AC_CHECK_HEADERS([sqlite3.h], [want_sqlite3=yes], [want_sqlite3=no])
if test "x$want_sqlite3" = "xyes"
then
	AC_CHECK_LIB([sqlite3], [sqlite3_unlock_notify], [AC_DEFINE([HAVE_SQLITE3_UNLOCK_NOTIFY], ,[Sqlite3 unlock notify API])])
	DATASTORE_OBJS="$DATASTORE_OBJS datastore_sqlite.la"
fi

# Check for MySQL
AC_CHECK_HEADERS([mysql/mysql.h], [want_mysql=yes], [want_mysql=no])
if test "x$want_mysql" = "xyes"
then
	DATASTORE_OBJS="$DATASTORE_OBJS datastore_mysql.la"
fi

# Check for Zlib
AC_CHECK_HEADERS([zlib.h], [want_zlib=yes], [want_zlib=no])
if test "x$want_zlib" = "xyes"
then
	AC_DEFINE(HAVE_ZLIB, , [Zlib])
	zlib_LIBS="-lz"
	AC_SUBST(zlib_LIBS)
fi
#

AC_SUBST(INPUT_OBJS)
AC_SUBST(TARGET_OBJS)
AC_SUBST(DATASTORE_OBJS)

AC_OUTPUT

echo ""
echo "=============================================================="                                                              
echo "               |         |                         |    o     "
echo ",---.,---.,---.|__/ ,---.|---    ,---.   ,-.-.,---.|--- .,---."
echo "|   |,---||    |  \ |---'|    ---|   |---| | |,---||    ||    "
echo "|---'\`---^\`---'\`   \`\`---'\`---'   \`---'   \` ' '\`---^\`---'\`\`---'"
echo "|"
echo "=============================================================="
echo " Configuration result :"
echo " ----------------------"
echo ""
echo " * Found libpcap      : $want_pcap"
echo " * Found xmlrpc-c     : $want_xmlrpc"
echo " * Linux raw socket   : $want_netpacket"
echo " * Linux DVB headers  : $want_dvb"
echo " * Linux TUN headers  : $want_tun"
echo " * PostgreSQL headers : $want_postgres"
echo " * Sqlite3 headers    : $want_sqlite3"
echo " * MySQL headers      : $want_mysql"
echo " * Zlib headers       : $want_zlib"
echo ""
echo "Author : Guy Martin <gmsoft@tuxicoman.be>"


