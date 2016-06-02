#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
struct NetSpeedItem{
		int up;
		int down;
		int pid;
};
struct NetSpeedSet{
		struct NetSpeedItem *ns;
		int len;
};
struct NetSpeedSet * queryPidNetStream(char * pidstr, char * netcard);
void freeSet(struct NetSpeedSet * p);
