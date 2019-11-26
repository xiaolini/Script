#ifndef _UDPCON_H_
#define _UDPCON_H_

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "dataList.h"
#include "globalData.h"

struct udpCon_st 
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
	
	int srcPortRandom;
	int srcPortValue;
	//datalist_arr * srcPortls;
	unsigned short srcport_s;
	unsigned short srcport_e;
	int srcPortMeth;

	struct udphdr * udpHeader;
	struct iphdr * ipHeader;
		
	int dataRandom;
	char dataValue[MAXLENGTH];
	datalist_arr * datals;
	int dataMeth;
};

typedef struct udpCon_st udpCon;

#endif
