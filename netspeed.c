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

//@TODO ipv6 的支持

//端口的现在就不做了，因为使用netatop内核级别的统计
//但是因为netatop 在docker里面有问题，所以还是需要继续写
//
///pro/net/tcp udp文件都出来已经是网络字节序了，不用再转换了
//

#define MAX_PID_LENGTH 10
#define MAX_FDLINK 64

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
pcap_t* device;
typedef struct{
    u_int16_t dport;
    u_int16_t sport;
    int sa_family;
    int inode;
    int use;
    int ubyte;
    int dbyte;
    int protocol; //utp or tcp
    union{
        struct in6_addr ip6;
        struct in_addr ip4;
    }srcip;
    union{
        struct in6_addr ip6;
        struct in_addr ip4;
    }dstip;
}Connection;
//一个Pid下面有很多个链接
typedef struct {
    pid_t pid;
    Connection * conn;
    int cap;
    int len;
    int exist; //可能这个pid的进程已经不存在了
}Pid;
typedef struct{
    Pid *p;
    int len;
    int cap;
} PidSet;



//对于UDP来说要用到isUp，因为之比较端口可能peer的端口和本机UDP端口一样
//所以如果是上行流量只对比源的端口，是下行只比较目的的端口
//基于/proc/net/udp(tcp) 的local_address肯定是本机地址，所以tcp也可以使用
//isUp来判断，这样会少一些操作
//这个查找拆为两个函数
//针对udp如下:
//UDP没有链接，所以如果是本机监听udp端口，/pro/net/udp下面只有local_address有本机地址和监听的端口
//如果UDP是客户端，则只有/pro/net/udp下面只local_address有值，并且只有端口值，ip值全为0
//本机UDP端口又不可能重复，所以UDP只需要比较端口号就行了
Connection * upFindConnectionByUdp(PidSet *p, char * sip, u_int16_t sp, char * dip, 
                u_int16_t dp){
    int i, j;
    for(i = 0; i < p->len; i++){
        if(p->p[i].exist == 0)
            continue;
        for(j = 0; j < p->p[i].len; j++){
            if(!p->p[i].conn[j].use)
                continue;
            if(p->p[i].conn[j].sport == sp)
                return &p->p[i].conn[j];
        }
    }
    return NULL;
}
Connection * upFindConnectionByTcp(PidSet *p, char * sip, u_int16_t sp, char * dip, 
                u_int16_t dp){
    int i, j;
//    printf("s: %x   d: %x\n", *(int *)(sip), *(int*)(dip));
    for(i = 0; i < p->len; i++){
        if(p->p[i].exist == 0)
            continue;
        for(j = 0; j < p->p[i].len; j++){
            if(!p->p[i].conn[j].use)
                continue;
            if(memcmp(&(p->p[i].conn[j].srcip.ip4), sip, 4)  == 0 && 
                    memcmp(&(p->p[i].conn[j].dstip.ip4), dip, 4)  == 0 &&
                        p->p[i].conn[j].sport == sp && p->p[i].conn[j].dport == dp)
                    return &p->p[i].conn[j];
        }
    }
    return NULL;
}
Connection * downFindConnectionByUdp(PidSet *p, char * sip, u_int16_t sp, char * dip, 
                u_int16_t dp){
    int i, j;
    for(i = 0; i < p->len; i++){
        if(p->p[i].exist == 0)
            continue;
        for(j = 0; j < p->p[i].len; j++){
            if(!p->p[i].conn[j].use)
                continue;
            if(p->p[i].conn[j].sport == dp)
                return &p->p[i].conn[j];
        }
    }
    return NULL;
}
Connection * downFindConnectionByTcp(PidSet *p, char * sip, u_int16_t sp, char * dip, 
                u_int16_t dp){
    int i, j;
    for(i = 0; i < p->len; i++){
        if(p->p[i].exist == 0)
            continue;
        for(j = 0; j < p->p[i].len; j++){
            if(!p->p[i].conn[j].use)
                continue;
            if(memcmp(&(p->p[i].conn[j].srcip.ip4), dip, 4)  == 0 && 
                    memcmp(&(p->p[i].conn[j].dstip.ip4), sip, 4)  == 0 &&
                       p->p[i].conn[j].dport == sp && p->p[i].conn[j].sport == dp)
                    return &p->p[i].conn[j];
        }
    }
    return NULL;
}

int capture_packet1(pcap_t* device, PidSet * p, char * localip)
{
    struct iphdr *pip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct ether_header *eth;
    Connection * conn;
    struct pcap_pkthdr packet;
    char errbuf[1024]={0};
    char s1[20]={0};
    char s2[20]={0};
    int isUp;
    //capture the packet        
    const u_char* pkt=pcap_next(device,&packet);
    if(!pkt){
        printf("couldn't capture packet: %s\n",errbuf);
        return 1;
    }
    eth = (struct ether_header *) pkt;

/*
    //现在都是ip包，也没有必要检查
    if(eth->ether_type == ntohs(ETHERTYPE_IP)){
        return 0;
    }
*/
    pip = (struct iphdr *)(pkt + 14);

#ifdef DEBUG 
    //output the pacaket length byte and time
    inet_ntop(AF_INET, &pip->saddr, s1, 19);
    inet_ntop(AF_INET, &pip->daddr, s2, 19);
    printf("Packet length: %d Number of bytes:%d\n", packet.len, packet.caplen);  
    printf("Recieved time: %s ihl=%d\n", ctime((const time_t*)&packet.ts.tv_sec), pip->ihl * 4); 
    printf("s:%s  %x   d:%s %x\n", s1, (int)pip->saddr, s2, (int)pip->daddr);
#endif
    //这里没有比对端口，所以本机如果有多个进程指向同一台机器的tcp链接，就会所有都统计
    //所以解决办法@TODO findConnectionByIP4的时候检查tcp的端口
    isUp = memcmp(localip, (char *)(&pip->saddr), 4) == 0 ? 1 : 0;
    if(pip->protocol == TCP_PROTOCOL){ //tcp
        tcp = (struct tcphdr *)(pip->ihl * 4 + (char *)pip);
        if(isUp){
            conn = upFindConnectionByTcp(p, (char *)(&pip->saddr), ntohs(tcp->th_sport),
                           (char *)(&pip->daddr),ntohs(tcp->th_dport));
        }else{
            conn = downFindConnectionByTcp(p, (char *)(&pip->saddr), ntohs(tcp->th_sport),
                           (char *)(&pip->daddr),ntohs(tcp->th_dport));
        }
    }else if(pip->protocol == UDP_PROTOCOL){ //udp
        udp = (struct udphdr *)(pip->ihl * 4 + (char *)pip);
        if(isUp){
            conn = upFindConnectionByUdp(p, (char *)(&pip->saddr), ntohs(udp->uh_sport),
                           (char *)(&pip->daddr), ntohs(udp->uh_dport));
        }else{
            conn = downFindConnectionByUdp(p, (char *)(&pip->saddr), ntohs(udp->uh_sport),
                           (char *)(&pip->daddr), ntohs(udp->uh_dport));
        }
    }else
        return 0;
    if(conn){
//printf("found a connection---------->\n");
        if(!conn->use)
            return 0;
        if(isUp)
            conn->ubyte += packet.len;
        else
            conn->dbyte += packet.len;
    }
    return 0;
}

/*
 * s:  多少个Pid
 * cs: 每个pid多少条链接
 */
void initPidSet(PidSet * p, int s, int cs){
    int i;
    void * tmp;
    tmp = malloc(s*sizeof(Pid));
    assert(tmp != NULL);
    memset(tmp, 0, s*sizeof(Pid));
    p->p = (Pid*)tmp;
    p->len = 0;
    p->cap = s;

    for ( i = 0; i < s ; i ++){
        tmp = (void *)malloc(cs * sizeof(Connection));
        assert(tmp != NULL);
        memset(tmp, 0, cs * sizeof(Connection));
        p->p[i].len = 0;
        p->p[i].cap = cs;
        p->p[i].conn = (Connection *)tmp;
    }
    return ;
}
void reInitPidSet(PidSet * p, int s , int cs){
#ifdef DEBUG
    printf("=============reinitPidSet==============");
#endif
    int i;
    int prev_old_pid_cap;//上次的pid的cap值
    void * tmp;

    prev_old_pid_cap = p->cap;
    if(s > p->cap){
        tmp = malloc(s*sizeof(Pid));
        assert(tmp != NULL);
        memset(tmp, 0, s*sizeof(Pid));
        if(p->p != NULL){
            memcpy(tmp, p->p, p->cap * sizeof(Pid));
            free(p->p);
        }
        p->p = (Pid *)tmp;
        p->cap = s;
    }
    if(cs > p->p[0].cap){
        for ( i = 0; i < prev_old_pid_cap ; i ++){
            tmp = (void *)malloc(cs * sizeof(Connection));
            assert(tmp != NULL);
            memset(tmp, 0, cs * sizeof(Connection));
            if( p->p[i].conn != NULL ){
                memcpy(tmp, p->p[i].conn, p->p[i].cap * sizeof(Connection));
                free(p->p[i].conn);
            }
            p->p[i].cap = cs;
            p->p[i].conn = (Connection *)tmp;
        }
    }
    return ;
}

void release(PidSet *p){
    int i;
    if(p->p == NULL)
        return ;
    for(i = 0; i < p->cap; i++){
        if(p->p[i].conn != NULL){
            free(p->p[i].conn);
        }
    }
    if(p->p != NULL){
        free(p->p);
    }
    pcap_close(device);
}
void get_info_for_pid(PidSet * p, char * pid) {
    int i=0;
    char dirname[10 + MAX_PID_LENGTH];

    size_t dirlen = 10 + strlen(pid);
    snprintf(dirname, dirlen, "/proc/%s/fd", pid);

    DIR * dir = opendir(dirname);
    if (!dir) {
        p->p[p->len].exist = 0;
		return;
    }
    p->p[p->len].exist = 1;
    /* walk through /proc/%s/fd/... */
    struct dirent * entry;
    while ((entry = readdir(dir))) {
        if (entry->d_type != DT_LNK)
            continue;

        size_t fromlen = dirlen + strlen(entry->d_name) + 1;
        char fromname[10 + MAX_PID_LENGTH + 1 + MAX_FDLINK];
        snprintf (fromname, fromlen, "%s/%s", dirname, entry->d_name);

        int linklen = 80;
        char linkname [linklen];
        int usedlen = readlink(fromname, linkname, linklen-1);
        if (usedlen == -1)
        {
            continue;
        }
        assert (usedlen < linklen);
        linkname[usedlen] = '\0';
//        get_info_by_linkname (pid, linkname);
        if (strncmp(linkname, "socket:[", 8) == 0){
            char * tmp = strchr(linkname+8, ']');
            *tmp = 0;
            //printf("inode:%s\n", linkname+8);
            p->p[p->len].conn[i].inode = atoi(linkname+8);
            i++;
			if(i >= p->p[p->len].cap)
                reInitPidSet(p, p->cap, p->p[0].cap * 2);
        }
    }
    p->p[p->len].len = i;
    
}
Connection * findConnectionByInode(PidSet *p, int inode){
    int i, j;
    for(i = 0; i < p->len; i++){
        for(j = 0; j < p->p[i].len; j++){
            if(p->p[i].conn[j].inode == inode){
                return &p->p[i].conn[j];
            }
        }
    }
    return NULL;
}
void addtoconninode_udp (PidSet *p, char * buffer)
{
    int sa_family;
       struct in6_addr result_addr_local;

    char rem_addr[128], local_addr[128];
    //int local_port, rem_port;
    int local_port;
       struct in6_addr in6_local;

    Connection * pconn;
    // this leaked memory
    //unsigned long * inode = (unsigned long *) malloc (sizeof(unsigned long));
    unsigned long inode;

    int matches = sscanf(buffer, "%*d: %64[0-9A-Fa-f]:%X %*64[0-9A-Fa-f]:%*X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
        local_addr, &local_port, &inode);

    if (matches != 3) {
        fprintf(stderr,"Unexpected buffer: '%s'\n",buffer);
        exit(1);
    }
    if (inode == 0) {
        /* connection is in TIME_WAIT state. We rely on 
         * the old data still in the table. */
        return;
    }

    pconn = findConnectionByInode(p, inode);
    if(pconn == NULL)
        return ;

    if (strlen(local_addr) > 8)
    {
        /* this is an IPv6-style row */

        /* Demangle what the kernel gives us */
        sscanf(local_addr, "%08X%08X%08X%08X", 
            &in6_local.s6_addr32[0], &in6_local.s6_addr32[1],
            &in6_local.s6_addr32[2], &in6_local.s6_addr32[3]);

        if ((in6_local.s6_addr32[0] == 0x0) && (in6_local.s6_addr32[1] == 0x0)
            && (in6_local.s6_addr32[2] == 0xFFFF0000))
        {
            /* IPv4-compatible address */
            result_addr_local  = *((struct in6_addr*) &(in6_local.s6_addr32[3]));
            sa_family = AF_INET;
        } else {
            /* real IPv6 address */
            //inet_ntop(AF_INET6, &in6_local, addr6, sizeof(addr6));
            //INET6_getsock(addr6, (struct sockaddr *) &localaddr);
            //inet_ntop(AF_INET6, &in6_remote, addr6, sizeof(addr6));
            //INET6_getsock(addr6, (struct sockaddr *) &remaddr);
            //localaddr.sin6_family = AF_INET6;
            //remaddr.sin6_family = AF_INET6;
            result_addr_local  = in6_local;
            sa_family = AF_INET6;
        }
    }
    else
    {
        /* this is an IPv4-style row */
#if 0
        sscanf(local_addr, "%X", (unsigned int *) &result_addr_local);
        sscanf(rem_addr, "%X",   (unsigned int *) &result_addr_remote);
        sa_family = AF_INET;
#endif
        pconn->sa_family = AF_INET;
        sscanf(local_addr, "%X", (unsigned int *) &(pconn->srcip.ip4));
        sscanf(rem_addr, "%X",   (unsigned int *) &(pconn->dstip.ip4));
        pconn->sport = local_port;
        pconn->use = 1;
        pconn->protocol = UDP_PROTOCOL;
    }

}

void addtoconninode (PidSet *p, char * buffer)
{
    int sa_family;
       struct in6_addr result_addr_local;
       struct in6_addr result_addr_remote;

    char rem_addr[128], local_addr[128];
    char zerobuf[128]={0};
    //int local_port, rem_port;
    int local_port, rem_port;
       struct in6_addr in6_local;
       struct in6_addr in6_remote;

    Connection * pconn;
    // this leaked memory
    //unsigned long * inode = (unsigned long *) malloc (sizeof(unsigned long));
    unsigned long inode;

    int matches = sscanf(buffer, "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
        local_addr, &local_port, rem_addr, &rem_port, &inode);

    if (matches != 5) {
        fprintf(stderr,"Unexpected buffer: '%s'\n",buffer);
        exit(2);
    }
    
    
   //printf("sscanf port=%d %d\n",  local_port,rem_port);
    if (inode == 0) {
        /* connection is in TIME_WAIT state. We rely on 
         * the old data still in the table. */
        return;
    }

    pconn = findConnectionByInode(p, inode);
    if(pconn == NULL)
        return ;

    if (strlen(local_addr) > 8)
    {
        /* this is an IPv6-style row */

        /* Demangle what the kernel gives us */
        sscanf(local_addr, "%08X%08X%08X%08X", 
            &in6_local.s6_addr32[0], &in6_local.s6_addr32[1],
            &in6_local.s6_addr32[2], &in6_local.s6_addr32[3]);
        sscanf(rem_addr, "%08X%08X%08X%08X",
            &in6_remote.s6_addr32[0], &in6_remote.s6_addr32[1],
                   &in6_remote.s6_addr32[2], &in6_remote.s6_addr32[3]);

        if ((in6_local.s6_addr32[0] == 0x0) && (in6_local.s6_addr32[1] == 0x0)
            && (in6_local.s6_addr32[2] == 0xFFFF0000))
        {
            /* IPv4-compatible address */
            result_addr_local  = *((struct in6_addr*) &(in6_local.s6_addr32[3]));
            result_addr_remote = *((struct in6_addr*) &(in6_remote.s6_addr32[3]));
            sa_family = AF_INET;
        } else {
            /* real IPv6 address */
            //inet_ntop(AF_INET6, &in6_local, addr6, sizeof(addr6));
            //INET6_getsock(addr6, (struct sockaddr *) &localaddr);
            //inet_ntop(AF_INET6, &in6_remote, addr6, sizeof(addr6));
            //INET6_getsock(addr6, (struct sockaddr *) &remaddr);
            //localaddr.sin6_family = AF_INET6;
            //remaddr.sin6_family = AF_INET6;
            result_addr_local  = in6_local;
            result_addr_remote = in6_remote;
            sa_family = AF_INET6;
        }
    }
    else
    {
        /* this is an IPv4-style row */
#if 0
        sscanf(local_addr, "%X", (unsigned int *) &result_addr_local);
        sscanf(rem_addr, "%X",   (unsigned int *) &result_addr_remote);
        sa_family = AF_INET;
#endif
        //监听端口
        pconn->sa_family = AF_INET;
        sscanf(local_addr, "%X", (unsigned int *) &(pconn->srcip.ip4));
        sscanf(rem_addr, "%X",   (unsigned int *) &(pconn->dstip.ip4));
        if(memcmp(&(pconn->srcip.ip4), zerobuf, 4) == 0 || 
                        memcmp(&(pconn->dstip.ip4), zerobuf, 4) == 0)
            return ;
        pconn->sport = local_port;
        pconn->dport = rem_port;
        pconn->use = 1;
        pconn->protocol = TCP_PROTOCOL;
    }

}

int addPidSetConnection(PidSet *p, int pro){
    FILE * procinfo = NULL;
    if( pro == TCP_PROTOCOL){
        procinfo = fopen ("/proc/net/tcp", "r");
    }else{
        procinfo = fopen ("/proc/net/udp", "r");
    }

    char buffer[8192];

    assert(procinfo != NULL);
    
    fgets(buffer, sizeof(buffer), procinfo);

    do
    {
        if (fgets(buffer, sizeof(buffer), procinfo)){
            if(pro == TCP_PROTOCOL){
                addtoconninode(p, buffer);
            } else {
                addtoconninode_udp(p, buffer);
            }
        }
    } while (!feof(procinfo));

    fclose(procinfo);

    return 1;
}

void addPidSetInode(PidSet *p, char * pid){
    if(p->len == p->cap)
        reInitPidSet(p, p->cap * 2, p->p[0].cap);
    p->p[p->len].pid = atoi(pid);
    get_info_for_pid(p, pid);
    p->len++;
    return ;
}

int getIpByName(char *eth, char *ipaddr)
{
    int sock_fd;
    struct sockaddr_in  my_addr ;
    struct ifreq ifr;
   
    /**//* Get socket file descriptor */
    if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return -1;
    }
    /**//* Get IP Address */
    strcpy(ifr.ifr_name, eth);
   
    if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, ":No Such Device %s\n",eth);
        return -1;
    }
    memcpy(&my_addr, &ifr.ifr_addr, sizeof(my_addr));
//    printf( "localip:%s\n", inet_ntoa(my_addr.sin_addr));
    memcpy(ipaddr, &my_addr.sin_addr, sizeof(my_addr.sin_addr));
    close(sock_fd);
    return 0;
}

void printConn(PidSet *p){
    int i, j;

    printf("######################################\n");
    char * local_string = (char*) malloc (50);
    char * remote_string = (char*) malloc (50);
    for(i = 0; i < p->len; i++){
        for(j = 0; j < p->p[i].len; j++){
            Connection * conn =  &p->p[i].conn[j];
            printf("inode=%d\n", conn->inode);
            if(!conn->use)
                continue;
            inet_ntop(conn->sa_family, &(conn->srcip.ip4), local_string,  49);
            inet_ntop(conn->sa_family, &(conn->dstip.ip4), remote_string, 49);
            printf("\t%s  %15s:%d-%15s:%d \n", conn->protocol == TCP_PROTOCOL ? "tcp" : "udp",
                            local_string, conn->sport, remote_string, conn->dport);
        }
    }
    free (local_string);
    free (remote_string);
    printf("######################################\n");
}
char * printSpeed(PidSet *p, struct timeval *s, struct timeval *e){
    int i, j, n;
    char * tmp, *buffer ;
    int diff = 0;
    
    char local_string [50]={0};
    char remote_string [50]={0};
    
    buffer = (char *)malloc(10 * (p->len) * 2);//up dan down
    memset(buffer, 0, 10 * (p->len) * 2);
    tmp = buffer;
    diff = (e->tv_sec - s->tv_sec)*1000 + (e->tv_usec - s->tv_usec)/1000;
    for(i = 0; i < p->len; i++){
        int ucount = 0;
        int dcount = 0;
#ifdef DEBUG
        printf("pid:%d len:%2d connlen:%2d\n",
                        p->p[i].pid, p->len, p->p[i].len);
#endif
        for(j = 0; j < p->p[i].len; j++){
            Connection * conn =  &p->p[i].conn[j];
            if(!conn->use)
                continue;
            inet_ntop(conn->sa_family, &(conn->srcip.ip4), local_string,  49);
            inet_ntop(conn->sa_family, &(conn->dstip.ip4), remote_string, 49);
            ucount += conn->ubyte;
            dcount += conn->dbyte;
#ifdef DEBUG
            printf("\t%s  %15s:%d-%15s:%d    us:%d           ds:%d KBS\n",
                            conn->protocol == TCP_PROTOCOL ? "tcp" : "udp",
                               local_string, conn->sport, remote_string, 
                            conn->dport, conn->ubyte*1000/diff/1024, conn->dbyte*1000/diff/1024);
#endif
            conn->ubyte = 0;
            conn->dbyte = 0;
        }
        n = sprintf(tmp, "%d %d ", ucount*1000/diff/1024, dcount*1000/diff/1024);
        tmp += n;
#ifdef DEBUG
        printf("\t\t uspeed:%d  dspeed:%d  speed:%dKBs\n", ucount*1000/diff/1024,
                       dcount*1000/diff/1024, (ucount+dcount)*1000/diff/1024);
#endif
    }
    return buffer;
}

char * queryPidNetStream(int argc, char **argv, char * netcard)
{
    char errbuf[1024];
    char localip [10] ={0};
    PidSet ps;
    char * retstr = NULL;
    int i;

    if(getIpByName(netcard, localip)){
        perror( "get local ip fail\n");    
        exit(3);
    }
    initPidSet(&ps, 10, 5); 
    
    for(i = 0; i < argc; i++){
        addPidSetInode(&ps, argv[i]);
    }
#ifdef DEBUG
    int j;
    for(i = 0; i < ps.len; i++){
        j  = 0;
        while(ps.p[i].conn[j].inode != 0){
            printf("inode:%d\n", ps.p[i].conn[j].inode);
            j++;
        }
        printf("=================\n");
    }
    printf("--------------------------------------\n");
#endif
    addPidSetConnection(&ps, TCP_PROTOCOL);
    addPidSetConnection(&ps, UDP_PROTOCOL);

#ifdef DEBUG
    printConn(&ps);
#endif

//    printf("pcap_open_live netcard:%s\n", netcard);
    //open the finded device(must set :ifconfig eth0 promisc)
    device = pcap_open_live(netcard,60,1,500,errbuf);
    if(!device){
        printf("couldn't open the net device: %s\n",errbuf);
        return NULL;
    }


    int cappkgs;
    struct timeval start, end;
    gettimeofday(&start, NULL);
REBEG:
    cappkgs = 0;
    while(1){
        if(capture_packet1(device, &ps, localip))
            break;
        if(++cappkgs == 200)
            break;
    }
    gettimeofday(&end, NULL);
    //    printf("start:%d %d   end:%d %d\n", start.tv_sec, start.tv_usec, end.tv_sec, end.tv_usec);
    if( start.tv_sec == end.tv_sec && (start.tv_usec - end.tv_usec) < 10000) 
    //这里要测试下最佳时间，时间太大耗费性能，太小可能不准确
    //@TODO 0.1s到0.01秒之间测试下
        goto REBEG;

    retstr = printSpeed(&ps, &start, &end );
    release(&ps);
    return retstr;
}

int test1(int argc, char **argv){
    char * str;
    if(argc < 3){
        printf("usage as:%s ifname pid1 pid2 ...\n", argv[0]);
        exit (4);
    }
    str = queryPidNetStream(argc-2, argv+2, argv[1]);
    printf("%s\n", str);
    free(str);   
}

int test2(int argc, char **argv){
    char * str;
    int times;
    if(argc < 4){
        printf("usage as:%s ifname times pid1 pid2 ...\n", argv[0]);
        exit (5);
    }
    times = atoi(argv[2]);
    while(times--){
       str = queryPidNetStream(argc-3, argv+3, argv[1]);
       printf("len:%d result:%s\n",strlen(str), str);
       free(str);   
    }
}
int main(int argc, char **argv){
        //test1(argc, argv);
        test2(argc, argv);
}
