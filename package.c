/********************************************************************************/
/* 组包程序                                                                     */
/********************************************************************************/
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "synCon.h"
#include "udpCon.h"
#include "icmpCon.h"
#include "httpCon.h"
#include "dataList.h"
#include "package.h"
#include "globalData.h"
#include "packetTime.h"
/********************************************************************************/
/* check校验和                                                                  */
/********************************************************************************/
unsigned short checksum(unsigned short * data,unsigned short length)
{
    unsigned long sum=0;
    while (length > 1){
        sum += *data++;
        length -= sizeof(unsigned short);
    }
    if (length){
        sum += *(unsigned char *)data;
    }  
    sum = (sum >>16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}
/********************************************************************************/
/* 组织ip_tcp包                                                                 */
/********************************************************************************/
char *ip_tcp_package(synCon * synConTemp,char * attackipstr,char * attackportstr)
{
	struct iphdr * ip_header;
	struct tcphdr * tcp_header;
	char dataArrary[MAXLENGTH];//包数据
	char *datap;//指向包数据数组的指针
	char dataPac[MAXLENGTH];//负载数据
	char tcp_temp[MAXLENGTH+12];//记录tcp包校验数据(包括伪头，主要用于校验,12位伪头长度
	int packageLength = synConTemp->packetLength;
	int dataLength = packageLength-sizeof(struct iphdr)-sizeof(struct tcphdr);//填充数据长度：包长度－报文头长度
	struct psdhdr_tcp psdtcp_header;//tcp伪包头+tcp包头
	//init
	bzero(&dataPac,MAXLENGTH);
	bzero(&dataArrary,MAXLENGTH);
	bzero(&tcp_temp,MAXLENGTH+12);
	ip_header = (struct iphdr *)malloc(sizeof(struct iphdr));
	tcp_header = (struct tcphdr *)malloc(sizeof(struct tcphdr));
	//set IPHedaer
	ip_header->ihl=sizeof(struct iphdr)/4;//ip头长度
	ip_header->version=4;//版本号
	ip_header->tos=0;
	ip_header->tot_len = packageLength;
	ip_header->id=htons(random());
	ip_header->frag_off=0;
	ip_header->ttl=synConTemp->ipHeader->ttl;//生存时间
	ip_header->protocol=IPPROTO_TCP; //传输协议
	ip_header->check=0;
	if(synConTemp->srcIpAddressRandom==1) { //源ip地址随机
		if(synConTemp->srcIpMeth==1) { //均匀分布
			//ip_header->saddr=inet_addr(getSomeone_arr(synConTemp->srcIpls,getRandomNumber(getLinkLength_arr(synConTemp->srcIpls))));//获得随机伪造源ip地址
            ip_header->saddr = htonl(getRandomNumberFT(synConTemp->srcip_s,synConTemp->srcip_e));
			//printf("[%d]\n",getRandomNumber(getLinkLength_arr(synConTemp->srcIpls)));
		}
		else{
			////非均匀分布
		}
	}
	else { //源ip地址指定
		ip_header->saddr=inet_addr(synConTemp->srcIpValue);
	}
	ip_header->daddr = inet_addr(attackipstr);
	
	//set TCPHedaer
	//tcp_header = synConTemp->tcpHeader;
	if(synConTemp->srcPortRandom==1) { //源端口随机
		if(synConTemp->srcPortMeth==1) { //均匀分布
			tcp_header->source=htons(getRandomNumberFT(synConTemp->srcport_s,synConTemp->srcport_e));//获得随机伪造源端口号
		}
		else{
			////非均匀分布
		}	
	}
	else { //源端口号指定
		tcp_header->source=htons(synConTemp->srcPortValue);
	}
	unsigned int a = random();
	tcp_header->seq = htonl(a);
	tcp_header->ack_seq = synConTemp->tcpHeader->ack_seq;
	tcp_header->doff = synConTemp->tcpHeader->doff;
	tcp_header->urg = synConTemp->tcpHeader->urg;
	tcp_header->ack = synConTemp->tcpHeader->ack;
	tcp_header->psh = synConTemp->tcpHeader->psh;
	tcp_header->rst = synConTemp->tcpHeader->rst;
	tcp_header->syn = synConTemp->tcpHeader->syn;
	tcp_header->fin = synConTemp->tcpHeader->fin;
	tcp_header->window = synConTemp->tcpHeader->window;
	tcp_header->check = synConTemp->tcpHeader->check;
	tcp_header->urg_ptr = synConTemp->tcpHeader->urg_ptr;
	tcp_header->dest = htons(atoi(attackportstr));
	//set tcp伪头
	psdtcp_header.saddr = ip_header->saddr;
	psdtcp_header.daddr = ip_header->daddr;
	psdtcp_header.mbz=0;
	psdtcp_header.ptcl = IPPROTO_TCP;
	psdtcp_header.tcpl = htons(packageLength-sizeof(struct iphdr));//tcp包长度(包括tcp头部+tcp包负载数据)
	bcopy((char *)tcp_header,(char *)&psdtcp_header.tcpheader,sizeof(struct tcphdr));
	//set data/
	int i=0;
	char * getdataTemp;
	int datatemplen;
	if(dataLength>0){
		if(synConTemp->dataRandom==1) { //数据随机
			if(synConTemp->dataMeth==1) { //均匀分布
				int linklen = getLinkLength_arr(synConTemp->datals);
				bzero(dataPac,sizeof(dataPac));
				while(i<dataLength){
					getdataTemp=getSomeone_arr(synConTemp->datals,getRandomNumber(linklen));//获得随机数据
					datatemplen = strlen(getdataTemp);
					if(i+datatemplen<dataLength){
						memcpy(dataPac+i,getdataTemp,datatemplen);
						i=i+datatemplen;
					}
					else{
						break;
					}
				}
			}
			else{
				////非均匀分布
			}
		}
		else { //数据指定
			memset(dataPac,'1',sizeof(dataPac));//将数据字段全部初始为1
			memcpy(dataPac,synConTemp->dataValue,strlen(synConTemp->dataValue));
		}
	}
	//printf("dataPac:%s\n",dataPac);
	memcpy(tcp_temp,&psdtcp_header,sizeof(struct psdhdr_tcp));
	memcpy(tcp_temp+sizeof(struct psdhdr_tcp),&dataPac,dataLength);
	//get tcp checksum
	if(synConTemp->tcpHeader->check==0)
		tcp_header->check=checksum((unsigned short *)&tcp_temp,sizeof(struct psdhdr_tcp)+dataLength);
	else
		tcp_header->check=synConTemp->tcpHeader->check;
	//get ip checksum
	if(synConTemp->ipHeader->check!=0)
		ip_header->check=synConTemp->ipHeader->check;
	else
		ip_header->check=checksum((unsigned short *)&ip_header,sizeof(struct iphdr));
	memcpy(dataArrary,ip_header,sizeof(struct iphdr));
	memcpy(dataArrary+sizeof(struct iphdr),tcp_header,sizeof(struct tcphdr));
	//free
	if(tcp_header)
		free(tcp_header);
	if(ip_header)
		free(ip_header);
	
	if(dataLength>0)
		memcpy(dataArrary+sizeof(struct iphdr)+sizeof(struct tcphdr),dataPac,dataLength);
	datap = dataArrary;
	return datap;
}
/********************************************************************************/
/* 组织ip_udp包                                                                 */
/********************************************************************************/
char * ip_udp_package(udpCon * udpConTemp,char * attackipstr,char * attackportstr)
{
	struct iphdr * ip_header;
	struct udphdr * udp_header;
	int packageLength = udpConTemp->packetLength;
	int dataLength = packageLength-sizeof(struct iphdr)-sizeof(struct udphdr);//填充数据长度：包长度－报文头长度
	struct psdhdr_udp psdudp_header;
	char dataArrary[MAXLENGTH];//包数据
	char *datap;//指向包数据数组的指针
	char dataPac[MAXLENGTH];//包内负载数据
	char udp_temp[MAXLENGTH+12];//记录udp包内数据(包括伪头,主要用来校验)
	//init
	bzero(&dataPac, MAXLENGTH);
	bzero(&dataArrary, MAXLENGTH);
	bzero(&udp_temp,MAXLENGTH+12);
	ip_header = (struct iphdr *)malloc(sizeof(struct iphdr));
	udp_header = (struct udphdr *)malloc(sizeof(struct udphdr));
	//set IPHedaer
	//此处设置ipheader具体字段值,需要明确各字段含义,否则将导致发送包无法收到
	ip_header->ihl=sizeof(struct iphdr)/4;//ip头长度
	ip_header->version=4;//版本号
	ip_header->tos=0;
	ip_header->tot_len = packageLength;
	ip_header->id=htons(random()); 
	ip_header->frag_off=0;
	ip_header->ttl=udpConTemp->ipHeader->ttl;//生存时间
	ip_header->protocol=IPPROTO_UDP; 
	ip_header->check=0;
	
	if(udpConTemp->srcIpAddressRandom==1) { //随机
		if(udpConTemp->srcIpMeth==1) { //均匀分布
			ip_header->saddr=htonl(getRandomNumberFT(udpConTemp->srcip_s,udpConTemp->srcip_e));//获得源ip地址
		}
		else{
			////非均匀分布
		}	
	}
	else { //指定源ip地址
		ip_header->saddr=inet_addr(udpConTemp->srcIpValue);
	}
	ip_header->daddr = inet_addr(attackipstr);
	//set UDPHedaer
	if(udpConTemp->srcPortRandom==1) { //随机
		if(udpConTemp->srcPortMeth==1) { //均匀分布
			udp_header->source=htons(getRandomNumberFT(udpConTemp->srcport_s,udpConTemp->srcport_e));
            
		}
		else{
			////非均匀分布
		}
	}
	else { //源端口号指定
		udp_header->source=htons(udpConTemp->srcPortValue);
	}
	udp_header->dest = htons(atoi(attackportstr));
	//printf("udp_header->dest::%s\n",attackportstr);
	udp_header->len = htons(packageLength-sizeof(struct iphdr));//udp length
	udp_header->check = 0;
	//set udpDheader
	psdudp_header.saddr = ip_header->saddr;
	psdudp_header.daddr = ip_header->daddr;
	psdudp_header.mbz = 0;
	psdudp_header.ptcl = IPPROTO_UDP;
	psdudp_header.udpl = htons(packageLength-sizeof(struct iphdr));
	bcopy((char *)udp_header,(char *)&psdudp_header.udpheader,sizeof(struct udphdr));
	//set data
	int i=0;
	char * getdataTemp;
	int datatemplen;
	if(udpConTemp->dataRandom==1) { //数据随机
		if(udpConTemp->dataMeth==1) { //均匀分布
			bzero(dataPac,sizeof(dataPac));
			int linklen = getLinkLength_arr(udpConTemp->datals);
			while(i<dataLength){
				getdataTemp=getSomeone_arr(udpConTemp->datals,getRandomNumber(linklen));//获得随机数据
				datatemplen = strlen(getdataTemp);
				if(i+datatemplen<dataLength){
					memcpy(dataPac+i,getdataTemp,datatemplen);
					i=i+datatemplen;
				}
				else
					break;
			}
		}
		else{
			////非均匀分布
		}
	}
	else{//数据指定
		memset(dataPac,'1',sizeof(dataPac));
		memcpy(dataPac,udpConTemp->dataValue,strlen(udpConTemp->dataValue));
	}
	//printf("dataPac:%s\n",dataPac);
	memcpy(udp_temp,&psdudp_header,sizeof(psdudp_header));
	memcpy(udp_temp+sizeof(psdudp_header),&dataPac,dataLength);
	/*get udp checksum*/
	if(udpConTemp->udpHeader->check!=0)//如果用户没有设置则认为check为0
		udp_header->check = checksum((unsigned short *) &udp_temp,sizeof(psdudp_header)+dataLength);
	else
		udp_header->check =0;
	/*get ip checksum*/
	if(udpConTemp->ipHeader->check!=0)
		ip_header->check=udpConTemp->ipHeader->check;
	else
		ip_header->check=checksum((unsigned short *)&ip_header,sizeof(struct iphdr));
	//填充数据完成组包
	memcpy(dataArrary,ip_header,sizeof(struct iphdr));
	memcpy(dataArrary+sizeof(struct iphdr),udp_header,sizeof(struct udphdr));
	//free
	if(udp_header)
		free(udp_header);
	if(ip_header)
		free(ip_header);
	if(dataLength>0)
		memcpy(dataArrary+sizeof(struct iphdr)+sizeof(struct udphdr),dataPac,dataLength);
	datap = dataArrary;
	return datap;
}
/********************************************************************************/
/* 组织ip_icmp包                                                                */
/********************************************************************************/
char * ip_icmp_package(icmpCon * icmpConTemp,char * attackipstr,char * attackportstr)
{
	struct iphdr * ip_header;
	struct icmphdr * icmp_header;
	int packageLength = icmpConTemp->packetLength;
	int dataLength = packageLength-sizeof(struct iphdr)-sizeof(struct icmphdr);//填充数据长度：包长度－报文头长度
	char dataArrary[MAXLENGTH];//包数据
	char *datap;//指向包数据数组的指针
	char icmp_temp[MAXLENGTH];//icmp校验数据(icmp头+负载数据)
	char dataPac[MAXLENGTH];
	bzero(&dataPac, MAXLENGTH);
	bzero(&dataArrary, MAXLENGTH);
	bzero(&icmp_temp,MAXLENGTH);
	ip_header = (struct iphdr *)malloc(sizeof(struct iphdr));
	icmp_header = (struct icmphdr *)malloc(sizeof(struct icmphdr));
	//set IPHedaer
	//此处设置ipheader具体字段值,需要明确各字段含义,否则将导致发送包无法收到
	//填充IP首部
	ip_header->ihl=sizeof(struct iphdr)/4;//ip头长度
	ip_header->version=4;//版本号
	ip_header->tos=0;
	ip_header->tot_len = packageLength;
	ip_header->id=htons(random()); 
	ip_header->frag_off=0;
	ip_header->ttl=icmpConTemp->ipHeader->ttl;//生存时间 
	ip_header->protocol=IPPROTO_ICMP; 
	ip_header->check=0;
	if(icmpConTemp->srcIpAddressRandom==1) { //随机
		if(icmpConTemp->srcIpMeth==1) { //均匀分布
			ip_header->saddr=htonl(getRandomNumberFT(icmpConTemp->srcip_s,icmpConTemp->srcip_e));/*获得源ip地址*/
			//printf("ip_header->saddr::%d\n",ip_header->saddr);
			//printf("[%d]\n",getRandomNumber(getLinkLength_arr(icmpConTemp->srcIpls)));
			
		}
		else{
			//非均匀分布
		}
	}
	else { //指定源ip地址
		ip_header->saddr=inet_addr(icmpConTemp->srcIpValue);
	}
	ip_header->daddr = inet_addr(attackipstr);
	//printf("attackipstr::%s\n",attackipstr);
	//printf("ip_header->daddr::%d\n",ip_header->daddr);
	//set ICMPHedaer
	icmp_header->type = icmpConTemp->icmpHeader->type;
	icmp_header->code = icmpConTemp->icmpHeader->code;
	icmp_header->checksum = icmpConTemp->icmpHeader->checksum;
	//set data
	int i=0;
	char * getdataTemp;
	int datatemplen;
	if(icmpConTemp->dataRandom==1) { //数据随机
		if(icmpConTemp->dataMeth==1) { //均匀分布
			int linklen=getLinkLength_arr(icmpConTemp->datals);
			bzero(dataPac,sizeof(dataPac));
			while(i<dataLength){
				getdataTemp=getSomeone_arr(icmpConTemp->datals,getRandomNumber(linklen));//获得随机数据
				datatemplen = strlen(getdataTemp);
				if(i+datatemplen<dataLength){
					memcpy(dataPac+i,getdataTemp,datatemplen);
					i=i+datatemplen;
				}
				else
					break;
			}
		}
		else{
			////非均匀分布
		}
	}
	else { //数据指定
		memset(dataPac,'1',sizeof(dataPac));
		memcpy(dataPac,icmpConTemp->dataValue,strlen(icmpConTemp->dataValue));
	}
	//printf("dataPac:%s\n",dataPac);
	//get icmp checksum
	if(icmpConTemp->icmpHeader->checksum==0) { //需要计算正确的checksum
		memcpy(icmp_temp,icmp_header,sizeof(struct icmphdr));
		memcpy(icmp_temp+sizeof(struct icmphdr),dataPac,dataLength);
		icmp_header->checksum = checksum((unsigned short *)&icmp_temp,packageLength-sizeof(struct iphdr));
	}
	else
		icmp_header->checksum = icmpConTemp->icmpHeader->checksum;
	//get ip checksum
	if(icmpConTemp->ipHeader->check!=0)
		ip_header->check=icmpConTemp->ipHeader->check;
	else
		ip_header->check=checksum((unsigned short *)&ip_header,sizeof(struct iphdr));
	memcpy(dataArrary,ip_header,sizeof(struct iphdr));
	memcpy(dataArrary+sizeof(struct iphdr),icmp_header,sizeof(struct icmphdr));
	memcpy(dataArrary+sizeof(struct iphdr)+sizeof(struct icmphdr),dataPac,dataLength);
	//free
	if(icmp_header)
		free(icmp_header);
	if(ip_header)
		free(ip_header);
	datap = dataArrary;
	return datap;
}
/********************************************************************************/
/* 组织http包                                                                   */
/********************************************************************************/
char * http_package(httpCon * httpConTemp)
{
	int packageLength = httpConTemp->packetLength;
	int requestLength = strlen(httpConTemp->requestStr);
	char tempArrary[MAXLENGTH];
	char tempArrary2[MAXLENGTH];
	bzero(&tempArrary, sizeof(tempArrary));
	memcpy(tempArrary,httpConTemp->requestStr,strlen(httpConTemp->requestStr));
	int m=0,j=0;
	while(m<requestLength){
		if(tempArrary[m]=='\\'){
			if(tempArrary[m+1]=='r'){
				tempArrary2[j]='\r';
				m=m+2;
				j++;
			}
			else if(tempArrary[m+1]=='n'){
				tempArrary2[j]='\n';
				m=m+2;
				j++;
			}
		}
		else{
			tempArrary2[j]=tempArrary[m];
			j++;
			m++;
		}
	}
	int dataLength = packageLength-j-40;//填充数据长度：包长度－报文头长度
	char dataArrary[MAXLENGTH];//包数据
	char *datap;//指向包数据数组的指针
	char dataPac[MAXLENGTH];
	bzero(&dataPac, sizeof(dataPac));
	bzero(&dataArrary, sizeof(dataArrary));
	memcpy(dataArrary,tempArrary2,j);
	//set data
	int i=0;
	char * getdataTemp;
	int datatemplen;
	if(httpConTemp->dataRandom==1) { //数据随机
		if(httpConTemp->dataMeth==1) { //均匀分布
			int linklen = getLinkLength_arr(httpConTemp->datals);
			bzero(dataPac,sizeof(dataPac));
			while(i<dataLength){
				getdataTemp=getSomeone_arr(httpConTemp->datals,getRandomNumber(linklen));//获得随机数据
				datatemplen = strlen(getdataTemp);
				if(i+datatemplen<dataLength){
					memcpy(dataPac+i,getdataTemp,datatemplen);
					i=i+datatemplen;
				}
				else
					break;
			}
		}
		else{
			//非均匀分布
		}
	}
	else { //数据指定
		memset(dataPac,'1',sizeof(dataPac));
		memcpy(dataPac,httpConTemp->dataValue,strlen(httpConTemp->dataValue));
	}
	memcpy(dataArrary+j,dataPac,dataLength);
	datap = dataArrary;
	return datap;
}
