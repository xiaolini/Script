/*tcpflood的配置条件*/
#ifndef _SYNCON_H_
#define _SYNCON_H_

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "dataList.h"
#include "globalData.h"

struct synCon_st 
{
	char id;
	float percentage;
	int packetLength;
	
	int srcIpAddressRandom;//1为随机，2为指定
	char srcIpValue[16];
	//datalist_arr * srcIpls;
	unsigned int srcip_s;     //host order
	unsigned int srcip_e;     //host order
	int srcIpMeth;
	
	int srcPortRandom;
	int srcPortValue;
	//datalist_arr * srcPortls;
	unsigned short srcport_s;
	unsigned short srcport_e;
	int srcPortMeth;

	struct tcphdr * tcpHeader;
	struct iphdr * ipHeader;
		
	int dataRandom;
	char dataValue[MAXLENGTH];
	datalist_arr * datals;
	int dataMeth;
};

typedef struct synCon_st synCon;

#endif
