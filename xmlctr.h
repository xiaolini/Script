#ifndef _XMLCTR_H_
#define _XMLCTR_H_

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "synCon.h"
#include "udpCon.h"
#include "icmpCon.h"
#include "httpCon.h"
#include "packetTime.h"

typedef struct ddosConfig_st
{
	int mode;//1:singal;2:fixed
	int src_type;//0:ip;1:domain;
	char src_domain[512];//(if src==domain)
    int getip_time;//s(if src==domain)
	
	datalist_arr *ipls;//dst ip list
	datalist_arr *portls;//dst port list
	
	int startThreadNumber;//start pthread number
	int sendPacketNumber;//packet length
	
	int pulseyn;
	packetTime *packetTimels;
	int cycleTime;
	int pulseTime;
	int speed;

	int attackTime;//time(min)
	
	synCon * synStyle;
	udpCon * udpStyle;
	icmpCon * icmpStyle;
	httpCon * httpStyle;
}ddosConfig;

/********************************************************************************/
/* 读取xml配置文件放入结构体xmlctr_st中                                         */
/* 输入参数:xml文件名                                                           */
/* 输出:结构体xmlctr_s                                                          */
/********************************************************************************/
ddosConfig * parseDoc(char * docname);

void destroy_ddosConfig(ddosConfig *ddosc);

#endif

