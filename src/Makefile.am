CFLAGS += -Wall -DDEBUG -pthread

bin_PROGRAMS = packet-o-matic
packet_o_matic_SOURCES = main.c main.h rules.c rules.h input.c input.h match.c match.h conntrack.c conntrack.h jhash.h target.c target.h timers.c timers.h helper.c helper.h conf.c conf.h common.c common.h layer.c layer.h mgmtsrv.c mgmtsrv.h mgmtvty.c mgmtvty.h mgmtcmd.c mgmtcmd.h ptype.c ptype.h

packet_o_matic_CFLAGS = @libxml2_CFLAGS@ -DLIBDIR='"@LIB_DIR@"'
packet_o_matic_LDFLAGS = @LIBS@ @libxml2_LIBS@

INPUT_OBJS = @INPUT_OBJS@
MATCH_OBJS = match_docsis.la match_ethernet.la match_ipv4.la match_icmp.la match_ipv6.la match_icmpv6.la match_tcp.la match_udp.la match_rtp.la match_undefined.la match_linux_cooked.la
CONNTRACK_OBJS = conntrack_ipv4.la conntrack_ipv6.la conntrack_rtp.la conntrack_tcp.la conntrack_udp.la
HELPER_OBJS = helper_ipv4.la helper_tcp.la
TARGET_OBJS = target_display.la target_dump_payload.la target_http.la target_wave.la target_null.la @TARGET_OBJS@
PTYPES_OBJS = ptype_bool.la ptype_uint8.la ptype_uint16.la ptype_uint32.la ptype_mac.la ptype_ipv4.la ptype_ipv6.la ptype_string.la ptype_bytes.la


lib_LTLIBRARIES = $(INPUT_OBJS) $(MATCH_OBJS) $(CONNTRACK_OBJS) $(HELPER_OBJS) $(TARGET_OBJS) $(PTYPES_OBJS)
EXTRA_LTLIBRARIES = input_docsis.la input_pcap.la target_pcap.la target_tcpkill.la target_inject.la target_tap.la


input_docsis_la_SOURCES = input_docsis.c input_docsis.h modules_common.h
input_docsis_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
input_pcap_la_SOURCES = input_pcap.c input_pcap.h modules_common.h
input_pcap_la_LDFLAGS = -module -avoid-version -lpcap -rpath '$(libdir)'

match_docsis_la_SOURCES = match_docsis.c match_docsis.h modules_common.h
match_docsis_la_LDFLAGS = -module -avoid-version
match_ethernet_la_SOURCES = match_ethernet.c match_ethernet.h modules_common.h
match_ethernet_la_LDFLAGS = -module -avoid-version
match_ipv4_la_SOURCES = match_ipv4.c match_ipv4.h modules_common.h
match_ipv4_la_LDFLAGS = -module -avoid-version
match_icmp_la_SOURCES = match_icmp.c match_icmp.h modules_common.h
match_icmp_la_LDFLAGS = -module -avoid-version
match_ipv6_la_SOURCES = match_ipv6.c match_ipv6.h modules_common.h
match_ipv6_la_LDFLAGS = -module -avoid-version
match_icmpv6_la_SOURCES = match_icmpv6.c match_icmpv6.h modules_common.h
match_icmpv6_la_LDFLAGS = -module -avoid-version
match_tcp_la_SOURCES = match_tcp.c match_tcp.h modules_common.h
match_tcp_la_LDFLAGS = -module -avoid-version
match_udp_la_SOURCES = match_udp.c match_udp.h modules_common.h
match_udp_la_LDFLAGS = -module -avoid-version
match_rtp_la_SOURCES = match_rtp.c match_rtp.h modules_common.h
match_rtp_la_LDFLAGS = -module -avoid-version
match_undefined_la_SOURCES = match_undefined.c match_undefined.h modules_common.h
match_undefined_la_LDFLAGS = -module -avoid-version
match_linux_cooked_la_SOURCES = match_linux_cooked.c match_linux_cooked.h modules_common.h sll.h
match_linux_cooked_la_LDFLAGS = -module -avoid-version

conntrack_ipv4_la_SOURCES = conntrack_ipv4.c conntrack_ipv4.h modules_common.h jhash.h
conntrack_ipv4_la_LDFLAGS = -module -avoid-version
conntrack_ipv6_la_SOURCES = conntrack_ipv6.c conntrack_ipv6.h modules_common.h jhash.h
conntrack_ipv6_la_LDFLAGS = -module -avoid-version
conntrack_rtp_la_SOURCES = conntrack_rtp.c conntrack_rtp.h modules_common.h jhash.h
conntrack_rtp_la_LDFLAGS = -module -avoid-version
conntrack_tcp_la_SOURCES = conntrack_tcp.c conntrack_tcp.h modules_common.h jhash.h
conntrack_tcp_la_LDFLAGS = -module -avoid-version
conntrack_udp_la_SOURCES = conntrack_udp.c conntrack_udp.h modules_common.h jhash.h
conntrack_udp_la_LDFLAGS = -module -avoid-version

helper_ipv4_la_SOURCES = helper_ipv4.c helper_ipv4.h modules_common.h
helper_ipv4_la_LDFLAGS = -module -avoid-version
helper_tcp_la_SOURCES = helper_tcp.c helper_tcp.h modules_common.h
helper_tcp_la_LDFLAGS = -module -avoid-version


target_display_la_SOURCES = target_display.c target_display.h modules_common.h
target_display_la_LDFLAGS = -module -avoid-version
target_dump_payload_la_SOURCES = target_dump_payload.c target_dump_payload.h modules_common.h
target_dump_payload_la_LDFLAGS = -module -avoid-version
target_http_la_SOURCES = target_http.c target_http.h modules_common.h
target_http_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
target_inject_la_SOURCES = target_inject.c target_inject.h modules_common.h
target_inject_la_LDFLAGS = -module -avoid-version -lnet -rpath '$(libdir)'
target_pcap_la_SOURCES = target_pcap.c target_pcap.h modules_common.h
target_pcap_la_LDFLAGS = -module -avoid-version -lpcap -rpath '$(libdir)'
target_tap_la_SOURCES = target_tap.c target_tap.h modules_common.h
target_tap_la_LDFLAGS = -module -avoid-version -rpath '$(libdir)'
target_tcpkill_la_SOURCES = target_tcpkill.c target_tcpkill.h modules_common.h
target_tcpkill_la_LDFLAGS = -module -avoid-version -lnet -rpath '$(libdir)'
target_wave_la_SOURCES = target_wave.c target_wave.h modules_common.h
target_wave_la_LDFLAGS = -module -avoid-version
target_null_la_SOURCES = target_null.c target_null.h modules_common.h
target_null_la_LDFLAGS = -module -avoid-version

ptype_bool_la_SOURCES = ptype_bool.c ptype_bool.h modules_common.h
ptype_bool_la_LDFLAGS = -module -avoid-version
ptype_uint8_la_SOURCES = ptype_uint8.c ptype_uint8.h modules_common.h
ptype_uint8_la_LDFLAGS = -module -avoid-version
ptype_uint16_la_SOURCES = ptype_uint16.c ptype_uint16.h modules_common.h
ptype_uint16_la_LDFLAGS = -module -avoid-version
ptype_uint32_la_SOURCES = ptype_uint32.c ptype_uint32.h modules_common.h
ptype_uint32_la_LDFLAGS = -module -avoid-version
ptype_mac_la_SOURCES = ptype_mac.c ptype_mac.h modules_common.h
ptype_mac_la_LDFLAGS = -module -avoid-version
ptype_ipv4_la_SOURCES = ptype_ipv4.c ptype_ipv4.h modules_common.h
ptype_ipv4_la_LDFLAGS = -module -avoid-version
ptype_ipv6_la_SOURCES = ptype_ipv6.c ptype_ipv6.h modules_common.h
ptype_ipv6_la_LDFLAGS = -module -avoid-version
ptype_string_la_SOURCES = ptype_string.c ptype_string.h modules_common.h
ptype_string_la_LDFLAGS = -module -avoid-version
ptype_bytes_la_SOURCES = ptype_bytes.c ptype_bytes.h modules_common.h
ptype_bytes_la_LDFLAGS = -module -avoid-version
