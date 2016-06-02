#include "netspeed.h"

//@TODO ipv6 的支持

//现在就不做了，因为使用netatop内核级别的统计
//但是因为netatop 在docker里面有问题，所以还是需要继续写
//
///pro/net/tcp udp文件都出来已经是网络字节序了，不用再转换了

#define MAX_PID_LENGTH 10
#define MAX_FDLINK 64

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define MAX_IP_NUM 10
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

typedef struct{
    int type;
    union{
        struct in6_addr ip6;
        struct in_addr ip4;
    }ip;
}IpItem;
typedef struct{
    int len;
    IpItem * ips;
} IpSet;

IpSet ipSet = {0, NULL};
u_int16_t IPV4 = 0, IPV6 = 0;
PidSet ps = {0};
int pcap_all_offset = 0;
pcap_t* device;

void init(){
    IPV4 = ntohs(ETHERTYPE_IP);
    IPV6 = ntohs(ETHERTYPE_IPV6);
}

void freeSet(struct NetSpeedSet * _pNetSpeedSet){
    if(!_pNetSpeedSet)
        return;
    if(_pNetSpeedSet->ns){
        free(_pNetSpeedSet->ns);
        _pNetSpeedSet->ns=NULL;
    }
    free(_pNetSpeedSet);
}
// type: ETHERTYPE_IP for ipv4, ETHERTYPE_IPV6 for ipv6
int isLocalip(char * _pIp, int _nType){
    int i, len;
    len = (_nType==IPV6) ? 16 : 4;
//printf("len=%d ip=%x %d %x\n", len,  *((int *)_pIp), ipSet.len, *((int*) ipSet.ips));
    for(i = 0; i < ipSet.len; i++){
        if(memcmp(_pIp, ipSet.ips, 4) == 0)
            return 1;
    }
    return 0;
}

//对于UDP来说要用到isUp，因为只比较端口可能peer的端口和本机UDP端口一样
//所以如果是上行流量只对比源的端口，是下行只比较目的的端口
//基于/proc/net/udp(tcp) 的local_address肯定是本机地址，所以tcp也可以使用
//isUp来判断，这样会少一些操作
//针对udp如下:
//UDP没有链接，所以如果是本机监听udp端口，/pro/net/udp下面只有local_address有本机地址和监听的端口
//如果UDP是客户端，则只有/pro/net/udp下面只local_address的端口值，ip值全为0
//本机UDP端口又不可能重复，所以UDP只需要比较端口号就行了
Connection * upFindConnectionByUdp(PidSet *_pPidSet, char * _pSrcIp, u_int16_t _nSrcPort, char * _pDstIp, 
                u_int16_t _nDstPort){
    int i, j;
    for(i = 0; i < _pPidSet->len; i++){
        if(_pPidSet->p[i].exist == 0)
            continue;
        for(j = 0; j < _pPidSet->p[i].len; j++){
            if(!_pPidSet->p[i].conn[j].use)
                continue;
            if(_pPidSet->p[i].conn[j].sport == _nSrcPort)
                return &_pPidSet->p[i].conn[j];
        }
    }
    return NULL;
}
Connection * upFindConnectionByTcp(PidSet *_pPidSet, char * _pSrcIp, u_int16_t _nSrcPort, char * _pDstIp, 
                u_int16_t _nDstPort){
    int i, j;
//    printf("s: %x   d: %x\n", *(int *)(sip), *(int*)(dip));
    for(i = 0; i < _pPidSet->len; i++){
        if(_pPidSet->p[i].exist == 0)
            continue;
        for(j = 0; j < _pPidSet->p[i].len; j++){
            if(!_pPidSet->p[i].conn[j].use)
                continue;
            if(memcmp(&(_pPidSet->p[i].conn[j].srcip.ip4), _pSrcIp, 4)  == 0 && 
                    memcmp(&(_pPidSet->p[i].conn[j].dstip.ip4), _pDstIp, 4)  == 0 &&
                        _pPidSet->p[i].conn[j].sport == _nSrcPort && _pPidSet->p[i].conn[j].dport == _nDstPort)
                    return &_pPidSet->p[i].conn[j];
        }
    }
    return NULL;
}
Connection * downFindConnectionByUdp(PidSet *_pPidSet, char * _pSrcIp, u_int16_t _nSrcPort, char * _pDstIp, 
                u_int16_t _nDstPort){
    int i, j;
    for(i = 0; i < _pPidSet->len; i++){
        if(_pPidSet->p[i].exist == 0)
            continue;
        for(j = 0; j < _pPidSet->p[i].len; j++){
            if(!_pPidSet->p[i].conn[j].use)
                continue;
            if(_pPidSet->p[i].conn[j].sport == _nDstPort)
                return &_pPidSet->p[i].conn[j];
        }
    }
    return NULL;
}
Connection * downFindConnectionByTcp(PidSet *_pPidSet, char * _pSrcIp, u_int16_t _nSrcPort, char * _pDstIp, 
                u_int16_t _nDstPort){
    int i, j;
    for(i = 0; i < _pPidSet->len; i++){
        if(_pPidSet->p[i].exist == 0)
            continue;
        for(j = 0; j < _pPidSet->p[i].len; j++){
            if(!_pPidSet->p[i].conn[j].use)
                continue;
            if(memcmp(&(_pPidSet->p[i].conn[j].srcip.ip4), _pDstIp, 4)  == 0 && 
                    memcmp(&(_pPidSet->p[i].conn[j].dstip.ip4), _pSrcIp, 4)  == 0 &&
                       _pPidSet->p[i].conn[j].dport == _nSrcPort && _pPidSet->p[i].conn[j].sport == _nDstPort)
                    return &_pPidSet->p[i].conn[j];
        }
    }
    return NULL;
}

int capturePacket(pcap_t* _pPcapDev, PidSet * _pPidSet)
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
    const u_char* pkt=pcap_next(_pPcapDev, &packet);
    if(!pkt){
        printf("couldn't capture packet: %s\n",errbuf);
        return 1;
    }
    eth = (struct ether_header *) (pkt+pcap_all_offset);

    if(eth->ether_type == IPV6) {
        printf("ipv6 not surpported\n");
        return 0;
    }
//    printf("eth->ether_type=%x\n",eth->ether_type);
    //检查是否为ip协议
    if(eth->ether_type != IPV4){
    printf("not surpported protocol(only ip protocol) %x \n", eth->ether_type);
       // return 0;
    }
    pip = (struct iphdr *)((char *)eth + sizeof( struct ether_header));
    isUp = isLocalip((char *)(&pip->saddr), eth->ether_type);

#ifdef DEBUG 
    //output the pacaket length byte and time
    inet_ntop(AF_INET, &pip->saddr, s1, 19);
    inet_ntop(AF_INET, &pip->daddr, s2, 19);
    printf("%s:%d Plength: %d caples:%d  l3proctocl:%x ihl=%d \n",ctime((const time_t*)&packet.ts.tv_sec) ,isUp,
            packet.len, packet.caplen, eth->ether_type, pip->ihl * 4);  
#endif
    //这里没有比对端口，所以本机如果有多个进程指向同一台机器的tcp链接，就会所有都统计
    //所以解决办法@TODO findConnectionByIP4的时候检查tcp的端口
    if(pip->protocol == TCP_PROTOCOL){ //tcp
        tcp = (struct tcphdr *)(pip->ihl * 4 + (char *)pip);
        if(isUp){
            conn = upFindConnectionByTcp(_pPidSet, (char *)(&pip->saddr), ntohs(tcp->th_sport),
                           (char *)(&pip->daddr),ntohs(tcp->th_dport));
        }else{
            conn = downFindConnectionByTcp(_pPidSet, (char *)(&pip->saddr), ntohs(tcp->th_sport),
                           (char *)(&pip->daddr),ntohs(tcp->th_dport));
        }
#ifdef DEBUG 
printf("s:%s:%d   d:%s:%d %lx\n", s1, ntohs(tcp->th_sport), s2, ntohs(tcp->th_dport), conn);
#endif
    }else if(pip->protocol == UDP_PROTOCOL){ //udp
        udp = (struct udphdr *)(pip->ihl * 4 + (char *)pip);
        if(isUp){
            conn = upFindConnectionByUdp(_pPidSet, (char *)(&pip->saddr), ntohs(udp->uh_sport),
                           (char *)(&pip->daddr), ntohs(udp->uh_dport));
        }else{
            conn = downFindConnectionByUdp(_pPidSet, (char *)(&pip->saddr), ntohs(udp->uh_sport),
                           (char *)(&pip->daddr), ntohs(udp->uh_dport));
        }
#ifdef DEBUG 
printf("s:%s:%d   d:%s:%d  conn:%lx\n", s1, ntohs(udp->uh_sport), s2, ntohs(udp->uh_dport), conn);
#endif
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
void initPidSet(PidSet * _pPidSet, int _nPid, int _nPidConn){
    int i;
    void * tmp;
	if(_pPidSet->cap != 0){ //确保不会每次都分配内存
		for( i = 0; i < _pPidSet->cap ; i++){
			_pPidSet->p[i].len = 0;
			_pPidSet->len = 0;
	    }
		return;
	}
    tmp = malloc(_nPid * sizeof(Pid));
    assert(tmp != NULL);
    memset(tmp, 0, _nPid * sizeof(Pid));
    _pPidSet->p = (Pid*)tmp;
    _pPidSet->len = 0;
    _pPidSet->cap = _nPid ;

    for ( i = 0; i < _nPid  ; i ++){
        tmp = (void *)malloc(_nPidConn * sizeof(Connection));
        assert(tmp != NULL);
        memset(tmp, 0, _nPidConn * sizeof(Connection));
        _pPidSet->p[i].len = 0;
        _pPidSet->p[i].cap = _nPidConn;
        _pPidSet->p[i].conn = (Connection *)tmp;
    }
    return ;
}
void reInitPidSet(PidSet * _pPidSet, int _nPid, int _nPidConn){
#ifdef DEBUG
    printf("=============reinitPidSet==============\n");
#endif
    int i;
    int prev_old_pid_cap;//上次的pid的cap值
    void * tmp;

    prev_old_pid_cap = _pPidSet->cap;
    if(_nPid > _pPidSet->cap){
        tmp = malloc(_nPid * sizeof(Pid));
        assert(tmp != NULL);
        memset(tmp, 0, _nPid * sizeof(Pid));
        if(_pPidSet->p != NULL){
            memcpy(tmp, _pPidSet->p, _pPidSet->cap * sizeof(Pid));
            free(_pPidSet->p);
        }
        _pPidSet->p = (Pid *)tmp;
        _pPidSet->cap = _nPid;
    }
    if(_nPidConn > _pPidSet->p[0].cap){
        for ( i = 0; i < prev_old_pid_cap ; i ++){
            tmp = (void *)malloc(_nPidConn * sizeof(Connection));
            assert(tmp != NULL);
            memset(tmp, 0, _nPidConn * sizeof(Connection));
            if( _pPidSet->p[i].conn != NULL ){
                memcpy(tmp, _pPidSet->p[i].conn, _pPidSet->p[i].cap * sizeof(Connection));
                free(_pPidSet->p[i].conn);
            }
            _pPidSet->p[i].cap = _nPidConn;
            _pPidSet->p[i].conn = (Connection *)tmp;
        }
    }
    return ;
}

void release(PidSet * _pPidSet){
    int i;
    if(_pPidSet->p == NULL)
        return ;
    for(i = 0; i < _pPidSet->cap; i++){
        if(_pPidSet->p[i].conn != NULL){
            free(_pPidSet->p[i].conn);
        }
    }
    if(_pPidSet->p != NULL){
        free(_pPidSet->p);
    }
    pcap_close(device);
}
void getConnectionByPid(PidSet * _pPidSet, char * _pPidStr) {
    int i=0;
    char dirname[10 + MAX_PID_LENGTH];

    size_t dirlen = 10 + strlen(_pPidStr);
    snprintf(dirname, dirlen, "/proc/%s/fd", _pPidStr);

    DIR * dir = opendir(dirname);
    if (!dir) {
        _pPidSet->p[_pPidSet->len].exist = 0;
        return;
    }
    _pPidSet->p[_pPidSet->len].exist = 1;
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
            _pPidSet->p[_pPidSet->len].conn[i].inode = atoi(linkname+8);
            i++;
            if(i >= _pPidSet->p[_pPidSet->len].cap)
                reInitPidSet(_pPidSet, _pPidSet->cap, _pPidSet->p[0].cap * 2);
        }
    }
    _pPidSet->p[_pPidSet->len].len = i;
    
}
Connection * findConnectionByInode(PidSet *_pPidSet, int _nInode){
    int i, j;
    for(i = 0; i < _pPidSet->len; i++){
        for(j = 0; j < _pPidSet->p[i].len; j++){
            if(_pPidSet->p[i].conn[j].inode == _nInode){
                return &_pPidSet->p[i].conn[j];
            }
        }
    }
    return NULL;
}
void addUdpConnection (PidSet *_pPidSet, char * _sLineStr)
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

    int matches = sscanf(_sLineStr, "%*d: %64[0-9A-Fa-f]:%X %*64[0-9A-Fa-f]:%*X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
        local_addr, &local_port, &inode);

    if (matches != 3) {
        fprintf(stderr,"Unexpected buffer: '%s'\n", _sLineStr);
        exit(1);
    }
    if (inode == 0) {
        /* connection is in TIME_WAIT state. We rely on 
         * the old data still in the table. */
        return;
    }

    pconn = findConnectionByInode(_pPidSet, inode);
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

void addTcpConnection (PidSet * _pPidSet, char * _pLineStr)
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

    int matches = sscanf(_pLineStr, "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
        local_addr, &local_port, rem_addr, &rem_port, &inode);

    if (matches != 5) {
        fprintf(stderr,"Unexpected buffer: '%s'\n", _pLineStr);
        exit(2);
    }
    
    
   //printf("sscanf port=%d %d\n",  local_port,rem_port);
    if (inode == 0) {
        /* connection is in TIME_WAIT state. We rely on 
         * the old data still in the table. */
        return;
    }

    pconn = findConnectionByInode(_pPidSet, inode);
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

int addPidSetConnection(PidSet * _pPidSet, int _nProtocol){
    FILE * procinfo = NULL;
    char * tmp;
    if( _nProtocol == TCP_PROTOCOL){
        procinfo = fopen ("/proc/net/tcp", "r");
    }else{
        procinfo = fopen ("/proc/net/udp", "r");
    }

    char buffer[8192];

    assert(procinfo != NULL);
    
    //tmp = 消除编译警告
    tmp = fgets(buffer, sizeof(buffer), procinfo);

    do
    {
        if (fgets(buffer, sizeof(buffer), procinfo)){
            if(_nProtocol == TCP_PROTOCOL){
                addTcpConnection(_pPidSet, buffer);
            } else {
                addUdpConnection(_pPidSet, buffer);
            }
        }
    } while (!feof(procinfo));

    fclose(procinfo);

    return 1;
}

void addPidSetInode(PidSet * _pPidSet, char * _pPidStr){
    if(_pPidSet->len == _pPidSet->cap)
        reInitPidSet(_pPidSet, _pPidSet->cap * 2, _pPidSet->p[0].cap);
    _pPidSet->p[_pPidSet->len].pid = atoi(_pPidStr);
    getConnectionByPid(_pPidSet, _pPidStr);
    _pPidSet->len++;
    return ;
}

int getAllLocalip()
{
    int fd, intrface ;
    struct ifreq buf[MAX_IP_NUM];
    struct ifconf ifc;
    int ipLen = MAX_IP_NUM, i = 0;
    ipSet.ips = (IpItem*)malloc(sizeof(IpItem) * ipLen);
    assert(ipSet.ips != NULL);
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        ifc.ifc_len = sizeof(buf);
        // caddr_t,linux内核源码里定义的：typedef void *caddr_t；
        ifc.ifc_buf = (caddr_t)buf;
        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc)) {
            intrface = ifc.ifc_len/sizeof(struct ifreq);
            while (intrface-- > 0) {
                if(i >= ipLen)
                       break;
                if (!(ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface])))
                {
                char * t = (char *)&((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr;
                //if(t[0] == 127) break; //127也不要过滤
                memcpy(&ipSet.ips[i], t, 4);
                char *ip=(inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));
                printf("IP:%s\n", ip);
                i++;
             }
          }
       }
       close(fd);
       ipSet.len = i;
    }
    return 0;
}
int getIpByName(char *_pNetCardName, char * _pBuf)
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
        strcpy(ifr.ifr_name, _pNetCardName);

        if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0) {
                fprintf(stderr, ":No Such Device %s\n",_pNetCardName);
                return -1;
        }
        memcpy(&my_addr, &ifr.ifr_addr, sizeof(my_addr));
#ifdef DEBUG
        printf( "localip:%s\n", inet_ntoa(my_addr.sin_addr));
#endif
        memcpy(_pBuf, &my_addr.sin_addr, sizeof(my_addr.sin_addr));
        close(sock_fd);
        return 0;
}

void printConn(PidSet * _pPidSet){
        int i, j;

        printf("######################################\n");
        char * local_string = (char*) malloc (50);
        char * remote_string = (char*) malloc (50);
        for(i = 0; i < _pPidSet->len; i++){
                for(j = 0; j < _pPidSet->p[i].len; j++){
                        Connection * conn =  &_pPidSet->p[i].conn[j];
                        printf("pid=%d inode=%d\n",_pPidSet->p[i].pid, conn->inode);
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
void printSpeed(struct NetSpeedSet * _pResult, PidSet * _pPidSet, struct timeval *s, struct timeval *e){
        int i, j, n;
        char * tmp, *buffer ;
        int diff = 0;

        char local_string [50]={0};
        char remote_string [50]={0};


#ifdef DEBUG
        buffer = (char *)malloc(10 * (_pPidSet->len) * 2);//up dan down
        memset(buffer, 0, 10 * (_pPidSet->len) * 2);
        tmp = buffer;
#endif
        diff = (e->tv_sec - s->tv_sec)*1000 + (e->tv_usec - s->tv_usec)/1000;
        for(i = 0; i < _pPidSet->len; i++){
                int ucount = 0;
                int dcount = 0;
                int up = 0, down = 0;
#ifdef DEBUG
                printf("pid:%d len:%2d connlen:%2d\n",
                                _pPidSet->p[i].pid, _pPidSet->len, _pPidSet->p[i].len);
#endif
                for(j = 0; j < _pPidSet->p[i].len; j++){
                        Connection * conn =  &_pPidSet->p[i].conn[j];
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
                                        conn->dport, (conn->ubyte/diff)*(1000.0/1024.0), (conn->dbyte/diff)*(1000.0/1024.0));
#endif
                        conn->ubyte = 0;
                        conn->dbyte = 0;
                }
               up = (ucount/diff)*(1000.0/1024.0);
               down = (dcount/diff)*(1000.0/1024.0);
#ifdef DEBUG
                n = sprintf(tmp, "%d %d ", up, down);
                tmp += n;
                printf("\t\t uspeed:%d  dspeed:%d  speed:%dKBs\n", up, down, up+down);
#endif
                _pResult->ns[i].pid = _pPidSet->p[i].pid;
                _pResult->ns[i].up   = up;
                _pResult->ns[i].down = down;
        }
#ifdef DEBUG
        printf("%d result:%s\n", strlen(buffer), buffer);
        free(buffer);
#endif
}

struct NetSpeedSet * queryPidNetStream( char * _pPidsStr, char * _pNetCardName)
{
    char errbuf[1024];
    int i;
    struct NetSpeedSet * retset;
    char * tmp1, *tmp2;

    if(IPV4 == 0)
        init(); //IPV6 IPV4两个值，大端模式
//printf("%x %x\n", IPV4, IPV6);
    if(ipSet.ips) //本机ip地址，每次重新获得，可能有变化
        free(ipSet.ips);
    ipSet.ips = NULL;

    if(_pNetCardName != NULL && memcmp(_pNetCardName, "any", 3) != 0 ) {
        ipSet.len = 1;
 	    pcap_all_offset = 0;
        ipSet.ips = (IpItem*)malloc(sizeof(IpItem));
        assert(ipSet.ips != NULL);
        if(getIpByName(_pNetCardName, (char *)ipSet.ips)){
            perror( "get local ip fail\n");    
            exit(3);
        }
    }else{
	    pcap_all_offset = 2;
        ipSet.len = 0;
        if(getAllLocalip()){
            perror( "get ll local ip fail\n");    
            exit(4);
        }
    }

    initPidSet(&ps, 10, 5); 

    tmp1 = _pPidsStr;
    do{
        tmp2 = strchr(tmp1, ',');
        *tmp2 ++ = '\0';
        addPidSetInode(&ps, tmp1);
        tmp1 = tmp2;

    }while(*tmp2 != '\0');
        
#ifdef DEBUG
    int j;
    for(i = 0; i < ps.len; i++){
    j  = 0;
    printf("pid:%d\n", ps.p[i].pid);
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
    device = pcap_open_live(_pNetCardName, 60, 1, 500, errbuf);
    if(!device){
    printf("couldn't open the net device: %s\n",errbuf);
    return NULL;
    }
    printf("pcap_open_live errbuf:%s\n", errbuf);


    int cappkgs;
    struct timeval start, end;
    gettimeofday(&start, NULL);
REBEG:
    cappkgs = 0;
    while(1){
    if(capturePacket(device, &ps))
        break;
    if(++cappkgs == 200)
        break;
    }
    gettimeofday(&end, NULL);
    //    printf("start:%d %d   end:%d %d\n", start.tv_sec, start.tv_usec, end.tv_sec, end.tv_usec);
    if( start.tv_sec == end.tv_sec && (start.tv_usec - end.tv_usec) < 100000) 
    //这里要测试下最佳时间，时间太大耗费性能，太小可能不准确
    //@TODO 0.1s到0.01秒之间测试下
    goto REBEG;

    retset = (struct NetSpeedSet *)malloc(sizeof(struct NetSpeedSet));
    assert(retset != NULL);
    retset->len = ps.len;
    retset->ns = (struct NetSpeedItem *)malloc(retset->len * sizeof(struct NetSpeedItem));
    assert(retset->ns != NULL);
    memset(retset->ns, 0, retset->len * sizeof(struct NetSpeedItem));

    printSpeed(retset, &ps, &start, &end );
    return retset;
}
