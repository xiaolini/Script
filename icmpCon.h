#ifndef _ICMPCON_H_
#define _ICMPCON_H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "dataList.h"

struct icmpCon_st 
{
	char id;
	float percentage;
	int packetLength;
	
	int srcIpAddressRandom;
	char srcIpValue[16];
	//datalist_arr * srcIpls;
	unsigned int srcip_s;     //host order
	unsigned int srcip_e;     //host order
	int srcIpMeth;
	
	struct icmphdr * icmpHeader;
	struct iphdr * ipHeader;
		
	int dataRandom;
	char dataValue[MAXLENGTH];
	datalist_arr * datals;
	int dataMeth;
};

typedef struct icmpCon_st icmpCon;

#endif
