#ifndef _PACKAGE_H_
#define _PACKAGE_H_

/*TCPDHeader*/
struct psdhdr_tcp
{
        unsigned int saddr;/*32,IP from address*/
        unsigned int daddr;/*32,ip to address*/       
	unsigned char mbz;/*set empty*/
        unsigned char ptcl;/*protcol style*/
        unsigned short tcpl;/*TCP length*/ 
	struct tcphdr tcpheader;
};
//struct psdhdr_tcp psdtcp_header;
/*UDPDHeader*/
struct psdhdr_udp
{
	unsigned int saddr;/*32,IP from address*/
        unsigned int daddr;/*32,ip to address*/
        unsigned char mbz;/*set empty*/
        unsigned char ptcl;/*protcol style*/
    	unsigned short udpl;/*UDP length*/ 
    	struct udphdr udpheader;
};

//function:组织ip_tcp数据包
//input:ip_tcp配置，攻击ip，攻击端口
//output:ip_tcp数据包地址
char * ip_tcp_package(synCon * synConTemp,char * attackipstr,char * attackportstr);

//function:组织ip_udp数据包
//input:ip_udp配置，攻击ip，攻击端口
//output:ip_udp数据包地址
char * ip_udp_package(udpCon * udpConTemp,char * attackipstr,char * attackportstr);

//function:组织ip_icmp数据包
//input:ip_icmp配置，攻击ip，攻击端口
//output:ip_icmp数据包地址
char * ip_icmp_package(icmpCon * icmpConTemp,char * attackipstr,char * attackportstr);

//function:组织http数据包
//input:http配置，攻击ip，攻击端口
//output:http数据包地址
char * http_package(httpCon * httpConTemp);

#endif
