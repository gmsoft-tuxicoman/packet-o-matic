CFLAGS = -Wall -g -ggdb3 -DDEBUG -pipe
#CFLAGS = -Wall -O3 -pipe

#CFLAGS += -DNDEBUG

CORE_OBJS = input.o match.o conntrack.o target.o
CONNTRACK_OBJS = conntrack_ipv4.so # conntrack_udp.so
TARGET_OBJS = target_null.so target_inject.so target_pcap.so  target_tap.so
INPUT_OBJS = input_docsis.so input_pcap.so
MATCH_OBJS = match_undefined.so match_ethernet.so match_ipv4.so match_tcp.so match_udp.so
MAIN_OBJS = main.o common.o config.o
RULES_OBJS = rules.o

LIBS = -lpcap -ldl

all: packet-o-matic


%.so: %.c %.h
	gcc -shared -fPIC ${CFLAGS} $< -o $@


packet-o-matic: ${MAIN_OBJS} ${CORE_OBJS} ${MATCH_OBJS} ${INPUT_OBJS} ${TARGET_OBJS} ${RULES_OBJS} ${CONNTRACK_OBJS}
	gcc -o packet-o-matic ${LIBS} ${CORE_OBJS} ${MAIN_OBJS} ${RULES_OBJS}

input.o: input.h
conntrack.o: conntrack.h
common.o: common.h
config.o: config.h
target.o: target.h
rules.o: rules.h


clean:
	rm *.o *.so packet-o-matic
