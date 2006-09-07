CFLAGS = -Wall -g -ggdb3 -DDEBUG -pipe
#CFLAGS = -Wall -O3 -pipe

#CFLAGS += -DNDEBUG

CORE_OBJS = input.o match.o target.o
#CONNTRACK_OBJS = conntrack.o conntrack_ipv4.o conntrack_udp.o
TARGET_OBJS = target_null.so target_inject.so target_pcap.so  target_tap.so
INPUT_OBJS = input_docsis.so
MATCH_OBJS = match_undefined.so match_ethernet.so match_ipv4.so match_tcp.so match_udp.so
MAIN_OBJS = main.o common.o config.o
RULES_OBJS = rules.o

LIBS = -lpcap -ldl

all: doctricks


%.so: %.c %.h
	gcc -shared -fPIC ${CFLAGS} $< -o $@


doctricks: ${MAIN_OBJS} ${CORE_OBJS} ${MATCH_OBJS} ${INPUT_OBJS} ${TARGET_OBJS} ${RULES_OBJS} ${CONNTRACK_OBJS}
	gcc -o doctricks ${LIBS} ${CORE_OBJS} ${FILTERS_OBJS} ${MAIN_OBJS} ${RULES_OBJS} ${CONNTRACK_OBJS}

input.o: input.h
input_docsis.so: input_docsis.h

conntrack.o: conntrack.h
conntrack_ipv4.o: conntrack_ipv4.h
conntrack_udp.o: conntrack_udp.h

match_ethernet.o: match_ethernet.h
match_ipv4.o: match_ipv4.h
match_tcp.o: match_tcp.h
match_udp.o: match_udp.h

common.o: common.h
config.o: config.h

target.o: target.h
target_tap.o: target_tap.h
target_rtp.o: target_rtp.h
target_pcap.o: target_pcap.h
target_inject.o: target_inject.h

rules.o: rules.h


clean:
	rm *.o *.so doctricks
