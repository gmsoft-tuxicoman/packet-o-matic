
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
AC_CHECK_HEADERS([netinet/ip_var.h sys/endian.h])

# Linux specidic header files
AC_CHECK_HEADERS([mcheck.h linux/if_ether.h endian.h])


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
AC_CHECK_FUNCS([bzero gettimeofday inet_ntoa memmove memset socket strerror])


LIB_DL=''
AC_CHECK_LIB([dl], [dlopen], [LIB_DL='-ldl'])
LIBS=[$LIB_DL $LIBS]
AC_SUBST(d[LIB_DL])

AC_CHECK_HEADER([pcap.h])
AC_CHECK_LIB([pcap], [pcap_open_offline, pcap_open_dead, pcap_close], [want_pcap=yes], [want_pcap=no])


# Checks for packages.
PKG_CHECK_MODULES(libxml2, [libxml-2.0], [], [AC_MSG_ERROR([libxml2 is required to build this program])])
AC_SUBST(libxml2_CFLAGS)
AC_SUBST(libxml2_LIBS)

AC_CONFIG_FILES([Makefile
                 src/Makefile])

# #define LIB_DIR
LIB_DIR='${libdir}'
AC_SUBST(LIB_DIR)

#
# Select build targets
#


# Check for PCAP
if test "x$want_pcap" = "xyes"
then
	INPUT_OBJS="$INPUT_OBJS input_pcap.la"
	TARGET_OBJS="$TARGET_OBJS target_pcap.la"
fi

# Check for DVB
AC_CHECK_HEADERS([linux/dvb/dmx.h linux/dvb/frontend.h], [INPUT_DOCSIS='input_docsis.la'])
INPUT_OBJS="$INPUT_DOCSIS $INPUT_OBJS"

if test "x$INPUT_OBJS" = "x"
then
	AC_MSG_ERROR([No input could be compiled.])
fi

# Check for Linux' raw socket iface
AC_CHECK_HEADERS([linux/socket.h netpacket/packet.h], [TARGET_RAW_SOCKET='target_tcpkill.la target_inject.la'])
TARGET_OBJS="$TARGET_OBJS $TARGET_RAW_SOCKET"

# Check for Linux' tun header
AC_CHECK_HEADERS([linux/if_tun.h], [TARGET_TAP='target_tap.la'])
TARGET_OBJS="$TARGET_OBJS $TARGET_TAP"


AC_SUBST(INPUT_OBJS)
AC_SUBST(TARGET_OBJS)




AC_OUTPUT
