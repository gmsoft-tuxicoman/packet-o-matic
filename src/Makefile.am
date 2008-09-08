CFLAGS += -Wall -I$(srcdir)/include -D_XOPEN_SOURCE=600 --std=gnu99 -D__EXTENSIONS__ -D_DARWIN_C_SOURCE -D_GNU_SOURCE

MGMT_SRC = mgmtsrv.c mgmtsrv.h mgmtvty.c mgmtvty.h mgmtcmd.c mgmtcmd.h mgmtcmd_helper.c mgmtcmd_helper.h mgmtcmd_conntrack.c mgmtcmd_conntrack.h mgmtcmd_input.c mgmtcmd_input.h mgmtcmd_rule.c mgmtcmd_rule.h mgmtcmd_target.c mgmtcmd_target.h

if USE_XMLRPC
wwwdir = $(pkgdatadir)/web-ui
XMLRPC_SRC = xmlrpcsrv.c xmlrpcsrv.h xmlrpccmd.c xmlrpccmd.h xmlrpccmd_input.c xmlrpccmd_input.h xmlrpccmd_helper.c xmlrpccmd_helper.h xmlrpccmd_conntrack.c xmlrpccmd_conntrack.h xmlrpccmd_rules.c xmlrpccmd_rules.h xmlrpccmd_match.c xmlrpccmd_match.h xmlrpccmd_target.c xmlrpccmd_target.h
endif

BUILT_SOURCES = svnversion.h
VERSION_SRC = version.h release.h svnversion.h

bin_PROGRAMS = packet-o-matic
packet_o_matic_SOURCES = main.c main.h rules.c rules.h conf.c conf.h layer.c layer.h $(VERSION_SRC) $(MGMT_SRC) $(XMLRPC_SRC)
packet_o_matic_CFLAGS = @libxml2_CFLAGS@ -DLIBDIR='"@LIB_DIR@"' -DWWWROOT='"$(wwwdir)"'
packet_o_matic_LDFLAGS = @LIBS@ @libxml2_LIBS@
packet_o_matic_LDADD = libpom.la @xmlrpc_LIBS@

noinst_HEADERS = include/jhash.h

libpom_la_SOURCES = input.c input.h match.c match.h conntrack.c conntrack.h target.c target.h timers.c timers.h helper.c helper.h ptype.c ptype.h expectation.c expectation.h common.c common.h include/jhash.h
libpom_la_CFLAGS = -DLIBDIR='"@LIB_DIR@"'

INPUT_OBJS = @INPUT_OBJS@
MATCH_OBJS = match_docsis.la match_ethernet.la match_vlan.la match_ipv4.la match_icmp.la match_ipv6.la match_icmpv6.la match_tcp.la match_udp.la match_rtp.la match_undefined.la match_linux_cooked.la
CONNTRACK_OBJS = conntrack_ipv4.la conntrack_ipv6.la conntrack_rtp.la conntrack_tcp.la conntrack_udp.la
HELPER_OBJS = helper_ipv4.la helper_tcp.la helper_rtp.la
TARGET_OBJS = target_display.la target_dump_payload.la target_irc.la target_http.la target_msn.la target_pop.la target_rtp.la target_tftp.la target_null.la @TARGET_OBJS@
PTYPES_OBJS = ptype_bool.la ptype_uint8.la ptype_uint16.la ptype_uint32.la ptype_uint64.la ptype_mac.la ptype_ipv4.la ptype_ipv6.la ptype_string.la ptype_bytes.la ptype_interval.la


lib_LTLIBRARIES = libpom.la $(INPUT_OBJS) $(MATCH_OBJS) $(CONNTRACK_OBJS) $(HELPER_OBJS) $(TARGET_OBJS) $(PTYPES_OBJS)
EXTRA_LTLIBRARIES = input_docsis.la input_pcap.la target_pcap.la target_tcpkill.la target_inject.la target_tap.la


input_docsis_la_SOURCES = input_docsis.c input_docsis.h modules_common.h include/docsis.h
input_docsis_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
input_docsis_la_LIBADD = libpom.la
input_pcap_la_SOURCES = input_pcap.c input_pcap.h modules_common.h
input_pcap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
input_pcap_la_LIBADD = libpom.la

match_docsis_la_SOURCES = match_docsis.c match_docsis.h modules_common.h include/docsis.h
match_docsis_la_LDFLAGS = -module -avoid-version
match_docsis_la_LIBADD = libpom.la
match_ethernet_la_SOURCES = match_ethernet.c match_ethernet.h modules_common.h include/ethernet.h
match_ethernet_la_LDFLAGS = -module -avoid-version
match_ethernet_la_LIBADD = libpom.la
match_vlan_la_SOURCES = match_vlan.c match_vlan.h modules_common.h include/vlan.h
match_vlan_la_LDFLAGS = -module -avoid-version
match_vlan_la_LIBADD = libpom.la
match_ipv4_la_SOURCES = match_ipv4.c match_ipv4.h modules_common.h
match_ipv4_la_LDFLAGS = -module -avoid-version
match_ipv4_la_LIBADD = libpom.la
match_icmp_la_SOURCES = match_icmp.c match_icmp.h modules_common.h
match_icmp_la_LDFLAGS = -module -avoid-version
match_icmp_la_LIBADD = libpom.la
match_ipv6_la_SOURCES = match_ipv6.c match_ipv6.h modules_common.h
match_ipv6_la_LDFLAGS = -module -avoid-version
match_ipv6_la_LIBADD = libpom.la
match_icmpv6_la_SOURCES = match_icmpv6.c match_icmpv6.h modules_common.h
match_icmpv6_la_LDFLAGS = -module -avoid-version
match_icmpv6_la_LIBADD = libpom.la
match_tcp_la_SOURCES = match_tcp.c match_tcp.h modules_common.h
match_tcp_la_LDFLAGS = -module -avoid-version
match_tcp_la_LIBADD = libpom.la
match_udp_la_SOURCES = match_udp.c match_udp.h modules_common.h
match_udp_la_LDFLAGS = -module -avoid-version
match_udp_la_LIBADD = libpom.la
match_rtp_la_SOURCES = match_rtp.c match_rtp.h modules_common.h include/rtp.h
match_rtp_la_LDFLAGS = -module -avoid-version
match_rtp_la_LIBADD = libpom.la
match_undefined_la_SOURCES = match_undefined.c match_undefined.h modules_common.h
match_undefined_la_LDFLAGS = -module -avoid-version
match_undefined_la_LIBADD = libpom.la
match_linux_cooked_la_SOURCES = match_linux_cooked.c match_linux_cooked.h modules_common.h include/sll.h
match_linux_cooked_la_LDFLAGS = -module -avoid-version
match_linux_cooked_la_LIBADD = libpom.la

conntrack_ipv4_la_SOURCES = conntrack_ipv4.c conntrack_ipv4.h modules_common.h include/jhash.h
conntrack_ipv4_la_LDFLAGS = -module -avoid-version
conntrack_ipv4_la_LIBADD = libpom.la
conntrack_ipv6_la_SOURCES = conntrack_ipv6.c conntrack_ipv6.h modules_common.h include/jhash.h
conntrack_ipv6_la_LDFLAGS = -module -avoid-version
conntrack_ipv6_la_LIBADD = libpom.la
conntrack_rtp_la_SOURCES = conntrack_rtp.c conntrack_rtp.h modules_common.h include/jhash.h include/rtp.h
conntrack_rtp_la_LDFLAGS = -module -avoid-version
conntrack_rtp_la_LIBADD = libpom.la
conntrack_tcp_la_SOURCES = conntrack_tcp.c conntrack_tcp.h modules_common.h include/jhash.h
conntrack_tcp_la_LDFLAGS = -module -avoid-version
conntrack_tcp_la_LIBADD = libpom.la
conntrack_udp_la_SOURCES = conntrack_udp.c conntrack_udp.h modules_common.h include/jhash.h
conntrack_udp_la_LDFLAGS = -module -avoid-version
conntrack_udp_la_LIBADD = libpom.la

helper_ipv4_la_SOURCES = helper_ipv4.c helper_ipv4.h modules_common.h
helper_ipv4_la_LDFLAGS = -module -avoid-version
helper_ipv4_la_LIBADD = libpom.la
helper_tcp_la_SOURCES = helper_tcp.c helper_tcp.h modules_common.h
helper_tcp_la_LDFLAGS = -module -avoid-version
helper_tcp_la_LIBADD = libpom.la
helper_rtp_la_SOURCES = helper_rtp.c helper_rtp.h modules_common.h include/rtp.h
helper_rtp_la_LDFLAGS = -module -avoid-version
helper_rtp_la_LIBADD = libpom.la


target_display_la_SOURCES = target_display.c target_display.h modules_common.h
target_display_la_LDFLAGS = -module -avoid-version
target_display_la_LIBADD = libpom.la
target_dump_payload_la_SOURCES = target_dump_payload.c target_dump_payload.h modules_common.h
target_dump_payload_la_LDFLAGS = -module -avoid-version
target_dump_payload_la_LIBADD = libpom.la
target_http_la_SOURCES = target_http.c target_http.h modules_common.h
target_http_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
target_http_la_LIBADD = libpom.la
target_inject_la_SOURCES = target_inject.c target_inject.h modules_common.h
target_inject_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
target_inject_la_LIBADD = libpom.la
target_irc_la_SOURCES = target_irc.c target_irc.h modules_common.h
target_irc_la_LDFLAGS = -module -avoid-version
target_irc_la_LIBADD = libpom.la
target_msn_la_SOURCES = target_msn.c target_msn.h target_msn_msgs.c target_msn_msgs.h target_msn_session.c target_msn_session.h modules_common.h
target_msn_la_LDFLAGS = -module -avoid-version
target_msn_la_LIBADD = libpom.la
target_pcap_la_SOURCES = target_pcap.c target_pcap.h modules_common.h
target_pcap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
target_pcap_la_LIBADD = libpom.la
target_tap_la_SOURCES = target_tap.c target_tap.h modules_common.h
target_tap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
target_tap_la_LIBADD = libpom.la
target_tcpkill_la_SOURCES = target_tcpkill.c target_tcpkill.h modules_common.h
target_tcpkill_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)' -lpcap
target_tcpkill_la_LIBADD = libpom.la
target_pop_la_SOURCES = target_pop.c target_pop.h modules_common.h
target_pop_la_LDFLAGS = -module -avoid-version
target_pop_la_LIBADD = libpom.la
target_rtp_la_SOURCES = target_rtp.c target_rtp.h modules_common.h include/rtp.h
target_rtp_la_LDFLAGS = -module -avoid-version
target_rtp_la_LIBADD = libpom.la
target_tftp_la_SOURCES = target_tftp.c target_tftp.h modules_common.h
target_tftp_la_LDFLAGS = -module -avoid-version
target_tftp_la_LIBADD = libpom.la
target_null_la_SOURCES = target_null.c target_null.h modules_common.h
target_null_la_LDFLAGS = -module -avoid-version
target_null_la_LIBADD = libpom.la

ptype_bool_la_SOURCES = ptype_bool.c ptype_bool.h modules_common.h
ptype_bool_la_LDFLAGS = -module -avoid-version
ptype_bool_la_LIBADD = libpom.la
ptype_uint8_la_SOURCES = ptype_uint8.c ptype_uint8.h modules_common.h
ptype_uint8_la_LDFLAGS = -module -avoid-version
ptype_uint8_la_LIBADD = libpom.la
ptype_uint16_la_SOURCES = ptype_uint16.c ptype_uint16.h modules_common.h
ptype_uint16_la_LDFLAGS = -module -avoid-version
ptype_uint16_la_LIBADD = libpom.la
ptype_uint32_la_SOURCES = ptype_uint32.c ptype_uint32.h modules_common.h
ptype_uint32_la_LDFLAGS = -module -avoid-version
ptype_uint32_la_LIBADD = libpom.la
ptype_uint64_la_SOURCES = ptype_uint64.c ptype_uint64.h modules_common.h
ptype_uint64_la_LDFLAGS = -module -avoid-version
ptype_uint64_la_LIBADD = libpom.la
ptype_mac_la_SOURCES = ptype_mac.c ptype_mac.h modules_common.h
ptype_mac_la_LDFLAGS = -module -avoid-version
ptype_mac_la_LIBADD = libpom.la
ptype_ipv4_la_SOURCES = ptype_ipv4.c ptype_ipv4.h modules_common.h
ptype_ipv4_la_LDFLAGS = -module -avoid-version
ptype_ipv4_la_LIBADD = libpom.la
ptype_ipv6_la_SOURCES = ptype_ipv6.c ptype_ipv6.h modules_common.h
ptype_ipv6_la_LDFLAGS = -module -avoid-version
ptype_ipv6_la_LIBADD = libpom.la
ptype_string_la_SOURCES = ptype_string.c ptype_string.h modules_common.h
ptype_string_la_LDFLAGS = -module -avoid-version
ptype_string_la_LIBADD = libpom.la
ptype_bytes_la_SOURCES = ptype_bytes.c ptype_bytes.h modules_common.h
ptype_bytes_la_LDFLAGS = -module -avoid-version
ptype_bytes_la_LIBADD = libpom.la
ptype_interval_la_SOURCES = ptype_interval.c ptype_interval.h modules_common.h
ptype_interval_la_LDFLAGS = -module -avoid-version
ptype_interval_la_LIBADD = libpom.la


.PHONY: svnversion.h.tmp
svnversion.h.tmp: 
	if [ -d .svn ]; then \
		ver=`svnversion -c . | sed -e 's/.*://' -e 's/[A-Za-z]//'`; \
		echo "#define POM_SVN_VERSION \"svn-r$$ver\"" > $@; \
	else \
		ver=`date +%F`; \
		echo "#define POM_SVN_VERSION \"built-$$ver\"" > $@; \
	fi
svnversion.h: svnversion.h.tmp
	diff $@ $@.tmp >/dev/null 2>&1 || cp -f $@.tmp $@; \
	rm -f $@.tmp

mostlyclean-local:
	rm -f svnversion.h svnversion.h.tmp

