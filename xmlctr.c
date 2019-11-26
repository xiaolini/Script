/********************************************************************************/
/* 读取xml配置文件                                                              */
/********************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "xmlctr.h"
#include "dataList.h"
#include "globalData.h"

static ddosConfig * ddosc;
static synCon * synConTemp;
static udpCon * udpConTemp;
static icmpCon * icmpConTemp;
static httpCon * httpConTemp;
static int ptime_from,ptime_to;

xmlChar * checkValue(xmlChar * temp)
{
	if(temp==NULL){
		xmlFree(temp);
		return NULL;
	}
	return temp;
}

/********************************************************************************/
/* 得到destIp属性值                                                             */
/* 返回值:1 success;0 fault                                                     */
/********************************************************************************/
static int parseDestIp (xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
    temp = xmlGetProp(cur,BAD_CAST("type"));
	if(temp!=NULL)
	{
		if(xmlStrcmp(temp,BAD_CAST("domain"))==0)
			ddosc->src_type = 1;
		else if(xmlStrcmp(temp,BAD_CAST("ip"))==0)
			ddosc->src_type = 0;
		else{
			printf("X Error: read xml 'destIp type' value Wrong.\n");
			return 0;
		}
	}
	
	temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
	if(temp!=NULL)
	{
	    if(ddosc->src_type==0)
		    ddosc->ipls = get_ls_arr((char *)temp);
		else
		{
		    //req domain's ip
		    strcpy(ddosc->src_domain,(char *)temp);
		    //printf("--**[%s]\n",ddosc->src_domain);
		    ddosc->ipls=req_domain_ip((char *)temp);
		}
	}
	else{
		printf("X Error: read xml 'destIp' Wrong.\n");
		xmlFree(temp);
		return 0;
	}
	xmlFree(temp);
	return 1;
}
/********************************************************************************/
/* 得到destPort属性值                                                           */
/* 返回值:1 success;0 fault                                                     */
/********************************************************************************/
static int parseDestPort (xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
	if(temp!=NULL){
		ddosc->portls = get_ls_arr((char *)temp);
	}
	else{
		printf("X Error: read xml 'destPort' Wrong.\n");
		xmlFree(temp);
		return 0;
	}
	xmlFree(temp);
	return 1;
}
int parsePacketTimeScope(xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	int ret = 1;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"from")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL){
				ptime_from = atoi((char *)temp);
			}
			else{
				printf("X Error: read xml 'packetTime.scope.from' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"to")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL){
				ptime_to = atoi((char *)temp);
			}
			else{
				printf("X Error: read xml 'packetTime.scope.to' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return ret;
}
/********************************************************************************/
/* 得到packetTime各属性                                                         */
/* 返回值:1 success;0 fault                                                     */
/********************************************************************************/
static int parsePacketTime (xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	int flag_ptime_random;
	int ptime_value,ptime_meth;
	int ret=1;
	temp = xmlGetProp(cur,BAD_CAST("random"));
	if(temp!=NULL){
		if(xmlStrcmp(temp,BAD_CAST("false"))==0)
			flag_ptime_random = 2;
		else
			flag_ptime_random = 1;
		xmlFree(temp);
		cur = cur->xmlChildrenNode;
		while(cur!=NULL){
			if(flag_ptime_random==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
				temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
				if(temp!=NULL){
					ptime_value = atoi((char *)temp);
				}
				else{
					printf("X Error: read xml 'packetTime.value' Wrong.\n");
					ret &= 0;
				}
				xmlFree(temp);
			}
			else if(flag_ptime_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope")){
				ret &= parsePacketTimeScope(doc,cur);
			}
			else if(flag_ptime_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
				temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
				if(temp!=NULL){
					ptime_meth = atoi((char *)temp);
				}
				else{
					printf("X Error: read xml 'packetTime.meth' Wrong.\n");
					ret &= 0;
				}
				xmlFree(temp);
			}
			cur = cur->next;
		}
		ddosc->packetTimels = get_packetTime(flag_ptime_random,
											ptime_value,
											ptime_from,ptime_to,ptime_meth);
	}
	else{
		printf("X Error: read xml 'packetTime.random' Wrong.\n");
		xmlFree(temp);
		return 0;
	}
	return ret;
}
/********************************************************************************/
/* 心跳攻击数据                                                                 */
/* 返回值:1 success;0 fault                                                     */
/********************************************************************************/
static int parsePulseData(xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	int ret=1;
	while(cur!=NULL){
		if((!xmlStrcmp(cur->name,(const xmlChar *)"cycleTime"))){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				ddosc->cycleTime=atoi((char *)temp);
			else{
				printf("X Error: read xml 'pulse.cycleTime' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		else if((!xmlStrcmp(cur->name,(const xmlChar *)"pulseTime"))){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				ddosc->pulseTime=atoi((char *)temp);
			else{
				printf("X Error: read xml 'pulse.pulseTime' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		else if((!xmlStrcmp(cur->name,(const xmlChar *)"speed"))){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				ddosc->speed=atoi((char *)temp);
			else{
				printf("X Error: read xml 'pulse.pulseTime' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return ret;
}
/********************************************************************************/
/* 得到GM各属性                                                                 */
/* 返回值:1 success;0 fault                                                     */
/********************************************************************************/
static int parseGenealMess (xmlDocPtr doc, xmlNodePtr cur)
{
	//generalMess节点id属性
	int ret=1;
	xmlChar * temp;
	temp = xmlGetProp(cur,BAD_CAST("id"));
	if(temp!=NULL){
		if(xmlStrcmp(temp,BAD_CAST("uniform"))==0){
			ddosc->pulseyn = 1;
		}
		else if(xmlStrcmp(temp,BAD_CAST("pulse"))==0){
			ddosc->pulseyn = 2;
		}
		else{
			printf("X Error: read xml 'generalMess.id' vlaue Wrong.\n");
			xmlFree(temp);
			ret &= 0;
		}
		xmlFree(temp);
		cur = cur->xmlChildrenNode;
		while(cur!=NULL){
			if(!xmlStrcmp(cur->name,(const xmlChar *)"startThreadNumber")){
				temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
				if(temp!=NULL){
					ddosc->startThreadNumber = atoi((char *)temp);
					if(ddosc->startThreadNumber>MAX_PTHREAD_NUM)
						ddosc->startThreadNumber = MAX_PTHREAD_NUM;
				}
				else{
					printf("X Error: read xml 'generalMess.startThreadNumber' Wrong.\n");
					ret &= 0;
				}
				xmlFree(temp);
			}
			else if(!xmlStrcmp(cur->name,(const xmlChar *)"sendPacketNumber")){
				temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
				if(temp!=NULL){
					ddosc->sendPacketNumber = atoi((char *)temp);
				}
				else{
					printf("X Error: read xml 'generalMess.sendPacketNumber' Wrong.\n");
					ret &= 0;
				}
				xmlFree(temp);
			}
			else if(ddosc->pulseyn==1&&!xmlStrcmp(cur->name,(const xmlChar *)"packetTime"))
				ret &= parsePacketTime(doc,cur);
			else if(ddosc->pulseyn==2&&!xmlStrcmp(cur->name,(const xmlChar *)"pulse"))
				ret &= parsePulseData(doc,cur);
			else if(!xmlStrcmp(cur->name,(const xmlChar *)"attackTime")){
				temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
				if(temp!=NULL){
					ddosc->attackTime = atoi((char *)temp);
				}
				else{
					printf("X Error: read xml 'generalMess.attackTime' Wrong.\n");
					ret &= 0;
				}
				xmlFree(temp);
			}
			cur = cur->next;
		}
	}
	else{
		printf("X Error: read xml 'generalMess.id' Wrong.\n");
		xmlFree(temp);
		return 0;
	}
	return ret;
}
/********************************************************************************/
/* 分别得到4种style的源ip报头属性                                               */
/********************************************************************************/
static int parseSynStyleSrcIp(xmlDocPtr doc, xmlNodePtr cur,int randomnum)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(randomnum==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			strcpy(synConTemp->srcIpValue,(char *)temp);
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			//synConTemp->srcIpls = get_ls_arr((char *)temp);
            if(temp)
            {
                char *p=strstr((char *)temp,",");
                int str_f_l=p-(char *)temp;
                char str_f[100];
                memcpy(str_f,(char *)temp,str_f_l);
                str_f[str_f_l]=0;

                synConTemp->srcip_s = ntohl(int_aton(str_f));
                synConTemp->srcip_e = ntohl(int_aton(p+1));

                printf("sip scope[%d][%s]-",synConTemp->srcip_s,str_f);
                printf("[%d][%s]\n",synConTemp->srcip_e,p+1);
            }
			
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			synConTemp->srcIpMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return 1;
}
static int parseUdpStyleSrcIp(xmlDocPtr doc, xmlNodePtr cur,int randomnum)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(randomnum==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			strcpy(udpConTemp->srcIpValue,(char *)temp);
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope"))
		{
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			//udpConTemp->srcIpls = get_ls_arr((char *)temp);
			if(temp)
            {
                char *p=strstr((char *)temp,",");
                int str_f_l=p-(char *)temp;
                char str_f[100];
                memcpy(str_f,(char *)temp,str_f_l);
                str_f[str_f_l]=0;

                udpConTemp->srcip_s = ntohl(int_aton(str_f));
                udpConTemp->srcip_e = ntohl(int_aton(p+1));

                printf("sip scope[%d][%s]-",udpConTemp->srcip_s,str_f);
                printf("[%d][%s]\n",udpConTemp->srcip_e,p+1);
            }
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			udpConTemp->srcIpMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return 1;
}
static int parseIcmpStyleSrcIp(xmlDocPtr doc, xmlNodePtr cur,int randomnum)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(randomnum==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			strcpy(icmpConTemp->srcIpValue,(char *)temp);
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope"))
		{
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			//icmpConTemp->srcIpls = get_ls_arr((char *)temp);
			if(temp)
            {
                char *p=strstr((char *)temp,",");
                int str_f_l=p-(char *)temp;
                char str_f[100];
                memcpy(str_f,(char *)temp,str_f_l);
                str_f[str_f_l]=0;

                icmpConTemp->srcip_s = ntohl(int_aton(str_f));
                icmpConTemp->srcip_e = ntohl(int_aton(p+1));

                printf("sip scope[%d][%s]-",icmpConTemp->srcip_s,str_f);
                printf("[%d][%s]\n",icmpConTemp->srcip_e,p+1);
            }
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			icmpConTemp->srcIpMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return 1;
}
/********************************************************************************/
/* 分别得到4种style的源端口报头属性                                             */
/********************************************************************************/
static int parseSynStyleSrcPort(xmlDocPtr doc, xmlNodePtr cur,int randomnum)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(randomnum==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			synConTemp->srcPortValue=atoi((char *)temp);
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			//synConTemp->srcPortls = get_ls_arr((char *)temp);

            if(temp)
            {
                char *p=strstr((char *)temp,",");
                int str_f_l=p-(char *)temp;
                char str_f[100];
                memcpy(str_f,(char *)temp,str_f_l);
                str_f[str_f_l]=0;

                synConTemp->srcport_s = atoi(str_f);
                synConTemp->srcport_e = atoi(p+1);

                printf("sport scope[%d]-[%d]\n",
                    synConTemp->srcport_s,synConTemp->srcport_e);
            }
			
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			synConTemp->srcPortMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return 1;
}
static int parseUdpStyleSrcPort(xmlDocPtr doc, xmlNodePtr cur,int randomnum)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(randomnum==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			udpConTemp->srcPortValue=atoi((char *)temp);
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope"))
		{
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			//udpConTemp->srcPortls = get_ls_arr((char *)temp);
            if(temp)
            {
			    char *p=strstr((char *)temp,",");
                int str_f_l=p-(char *)temp;
                char str_f[100];
                memcpy(str_f,(char *)temp,str_f_l);
                str_f[str_f_l]=0;

                udpConTemp->srcport_s = atoi(str_f);
                udpConTemp->srcport_e = atoi(p+1);

                printf("sport scope[%d]-[%d]\n",
                    udpConTemp->srcport_s,udpConTemp->srcport_e);
            }
            
			xmlFree(temp);
		}
		else if(randomnum==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			udpConTemp->srcPortMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return 1;
}
/********************************************************************************/
/* 得到tcp报头属性:填充tcp头除目的地址以外                                      */
/********************************************************************************/
static void parseTcpHeader(xmlDocPtr doc, xmlNodePtr cur)
{
	struct tcphdr * tcphdrTemp;
	tcphdrTemp = (struct tcphdr *)malloc(sizeof(struct tcphdr));
	memset(tcphdrTemp,0,sizeof(struct tcphdr));
	cur = cur->xmlChildrenNode;
	xmlChar * temp;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"ack_seq")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->ack_seq=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->ack_seq = 0;
			//printf("ack_seq:%d\n",tcphdrTemp->ack_seq);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"doff")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->doff=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->doff = sizeof(struct tcphdr)/4;
			//printf("doff:%d\n",tcphdrTemp->doff);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"urg")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->urg = atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->urg = 1;
			//printf("urg0:%d\n",tcphdrTemp->urg);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"ack")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->ack=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->ack = 1;
			//printf("ack:%d\n",tcphdrTemp->ack);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"psh")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->psh=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->psh = 1;
			//printf("psh:%d\n",tcphdrTemp->psh);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"rst")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->rst=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->rst = 1;
			//printf("rst:%d\n",tcphdrTemp->rst);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"syn")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->syn=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->syn = 1;
			//printf("syn:%d\n",tcphdrTemp->syn);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"fin")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->fin=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->fin = 1;
			//printf("fin:%d\n",tcphdrTemp->fin);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"window")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->window=htons(atoi((char *)temp));
			else//如果没有赋值则使用默认值
				tcphdrTemp->window = htons(65535);
			//printf("window:%d\n",tcphdrTemp->window);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"check")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->check=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->check = 0;
			//printf("check:%d\n",tcphdrTemp->check);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"urg_ptr")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				tcphdrTemp->urg_ptr=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				tcphdrTemp->urg_ptr = 0;
			//printf("urg_ptr:%d\n",tcphdrTemp->urg_ptr);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	synConTemp->tcpHeader = tcphdrTemp;
}
/********************************************************************************/
/* 得到ip报头属性                                                               */
/********************************************************************************/
static void parseIpHeader(xmlDocPtr doc, xmlNodePtr cur,int stylenum)
{
	struct iphdr * iphdrTemp;
	iphdrTemp = (struct iphdr *)malloc(sizeof(struct iphdr));
	memset(iphdrTemp,0,sizeof(struct iphdr));
	cur = cur->xmlChildrenNode;
	xmlChar * temp;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"versionihl")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->version=atoi((char *)temp);
			else
				iphdrTemp->version = 4;
			//printf("version:%d\n",iphdrTemp->version);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"tos")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->tos=atoi((char *)temp);
			else
				iphdrTemp->tos = 1;
			//printf("tos:%d\n",iphdrTemp->tos);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"tot_len")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->tot_len=atoi((char *)temp);
			else
				iphdrTemp->tot_len = 1;
			//printf("tot_len:%d\n",iphdrTemp->tot_len);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"id")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->id=atoi((char *)temp);
			else
				iphdrTemp->id = 1;
			//printf("id:%d\n",iphdrTemp->id);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"frag_off")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->frag_off=atoi((char *)temp);
			else
				iphdrTemp->frag_off = 1;
			//printf("frag_off:%d\n",iphdrTemp->frag_off);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"ttl")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->ttl=atoi((char *)temp);
			else
				iphdrTemp->ttl = 1;
			//printf("ttl:%d\n",iphdrTemp->ttl);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"protocol")){
			temp = 	xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->protocol=atoi((char *)temp);
			else
				iphdrTemp->protocol = 1;
			//printf("protocol:%d\n",iphdrTemp->protocol);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"check")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				iphdrTemp->check=atoi((char *)temp);
			else
				iphdrTemp->check = 0;
			//printf("check:%d\n",iphdrTemp->check);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	if(stylenum==1)
		synConTemp->ipHeader = iphdrTemp;
	else if(stylenum==2)
		udpConTemp->ipHeader = iphdrTemp;
	else if(stylenum==3)
		icmpConTemp->ipHeader = iphdrTemp;
}
/********************************************************************************/
/* 得到udp报头属性                                                              */
/********************************************************************************/
static void parseUdpHeader(xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	struct udphdr * udphdrTemp;
	udphdrTemp = (struct udphdr *)malloc(sizeof(struct udphdr));
	memset(udphdrTemp,0,sizeof(struct udphdr));
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"check")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				udphdrTemp->check=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				udphdrTemp->check = 0;
			//printf("check:%d\n",udphdrTemp->check);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	udpConTemp->udpHeader = udphdrTemp;
}
/********************************************************************************/
/* 得到icmp报头属性                                                             */
/********************************************************************************/
static void parseIcmpHeader(xmlDocPtr doc, xmlNodePtr cur)
{
	struct icmphdr * icmphdrTemp;
	icmphdrTemp = (struct icmphdr *)malloc(sizeof(struct icmphdr));
	memset(icmphdrTemp,0,sizeof(struct icmphdr));
	cur = cur->xmlChildrenNode;
	xmlChar *temp;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"type")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				icmphdrTemp->type=atoi((char *)temp);
			else//如果没有赋值则使用默认值
				icmphdrTemp->type = 8;
			//printf("type:%d\n",icmphdrTemp->type);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"code")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				icmphdrTemp->code=atoi((char *)temp);
			else
				icmphdrTemp->code = 0;
			//printf("code:%d\n",icmphdrTemp->code);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"check")){
			temp = 	xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				icmphdrTemp->checksum =atoi((char *)temp);
			else//如果没有赋值则使用默认值
				icmphdrTemp->checksum = 0;
			//printf("check:%d\n",icmphdrTemp->checksum);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	icmpConTemp->icmpHeader = icmphdrTemp;
}
/********************************************************************************/
/* 分别得到4种style属性dataHeader值                                             */
/********************************************************************************/
static void parseSynDataHeader(xmlDocPtr doc, xmlNodePtr cur)
{
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if((!xmlStrcmp(cur->name,(const xmlChar *)"tcpHeader"))){
			parseTcpHeader(doc,cur);
		}
		if((!xmlStrcmp(cur->name,(const xmlChar *)"ipHeader"))){
			parseIpHeader(doc,cur,1);
		}
		cur = cur->next;
	}
}
static void parseUdpDataHeader(xmlDocPtr doc, xmlNodePtr cur)
{
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if((!xmlStrcmp(cur->name,(const xmlChar *)"udpHeader")))
			parseUdpHeader(doc,cur);
		if((!xmlStrcmp(cur->name,(const xmlChar *)"ipHeader")))
			parseIpHeader(doc,cur,2);
		cur = cur->next;
	}
}
static void parseIcmpDataHeader(xmlDocPtr doc, xmlNodePtr cur)
{
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if((!xmlStrcmp(cur->name,(const xmlChar *)"icmpHeader")))
			parseIcmpHeader(doc,cur);
		if((!xmlStrcmp(cur->name,(const xmlChar *)"ipHeader")))
			parseIpHeader(doc,cur,3);
		cur = cur->next;
	}
}
static void parseHttpDataHeader(xmlDocPtr doc, xmlNodePtr cur)
{
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if((!xmlStrcmp(cur->name,(const xmlChar *)"httpRequest"))){
			xmlChar * temp;
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				strcpy(httpConTemp->requestStr,(char *)temp);
		}
		cur = cur->next;
	}
}
/********************************************************************************/
/* 分别得到4种style属性data值                                                   */
/********************************************************************************/
static void parseSynData(xmlDocPtr doc, xmlNodePtr cur,int flag_random)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(flag_random==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL){
				strcpy(synConTemp->dataValue,(char *)temp);
			}
			xmlFree(temp);
		}
		else if(flag_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				synConTemp->datals=get_ls_arr((char *)temp);
			xmlFree(temp);
		}
		else if(flag_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				synConTemp->dataMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
}
static void parseUdpData(xmlDocPtr doc, xmlNodePtr cur,int flag_random)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(flag_random==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				strcpy(udpConTemp->dataValue,(char *)temp);
			xmlFree(temp);
		}
		else if(flag_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				udpConTemp->datals=get_ls_arr((char *)temp);
			xmlFree(temp);
		}
		else if(flag_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				udpConTemp->dataMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
}
static void parseIcmpData(xmlDocPtr doc, xmlNodePtr cur,int flag_random)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(flag_random==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				strcpy(icmpConTemp->dataValue,(char *)temp);
			xmlFree(temp);
		}
		else if(flag_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"scope")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				icmpConTemp->datals=get_ls_arr((char *)temp);
			xmlFree(temp);
		}
		else if(flag_random==1&&!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				icmpConTemp->dataMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
}
static void parseHttpData(xmlDocPtr doc, xmlNodePtr cur,int flag_random)
{
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(flag_random==2&&!xmlStrcmp(cur->name,(const xmlChar *)"value")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				strcpy(httpConTemp->dataValue,(char *)temp);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"scope")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				httpConTemp->datals=get_ls_arr((char *)temp);
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"meth")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL)
				httpConTemp->dataMeth=atoi((char *)temp);
			xmlFree(temp);
		}
		cur = cur->next;
	}
}
/********************************************************************************/
/* 分别得到4种style属性值                                                       */
/********************************************************************************/
static int parseSynStyle(xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	int ret=1;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"packetLength")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL){
				synConTemp->packetLength=atoi((char *)temp);
				if(synConTemp->packetLength>MAXLENGTH)
					synConTemp->packetLength=MAXLENGTH;
			}
			else{
				printf("X Error: read xml 'style.packetLength' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"srcIpAddress")){
			temp = xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				synConTemp->srcIpAddressRandom = 1;
			else
				synConTemp->srcIpAddressRandom = 2;
			xmlFree(temp);
			parseSynStyleSrcIp(doc,cur,synConTemp->srcIpAddressRandom);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"srcPort")){
			temp = xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				synConTemp->srcPortRandom = 1;
			else
				synConTemp->srcPortRandom = 2;
			xmlFree(temp);
			parseSynStyleSrcPort(doc,cur,synConTemp->srcPortRandom);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"dataHeader")){
			parseSynDataHeader(doc,cur);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"data")){
			temp = xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				synConTemp->dataRandom = 1;
			else
				synConTemp->dataRandom = 2;
			xmlFree(temp);
			parseSynData(doc,cur,synConTemp->dataRandom);
		}
		cur = cur->next;
	}
	return ret;
}
static int parseUdpStyle(xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	int ret=1;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"packetLength")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL){
				udpConTemp->packetLength=atoi((char *)temp);
				if(udpConTemp->packetLength>MAXLENGTH)
					udpConTemp->packetLength=MAXLENGTH;
			}
			else{
				printf("X Error: read xml 'style.packetLength' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"srcIpAddress")){
			temp=xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				udpConTemp->srcIpAddressRandom = 1;
			else
				udpConTemp->srcIpAddressRandom = 2;
			xmlFree(temp);
			parseUdpStyleSrcIp(doc,cur,udpConTemp->srcIpAddressRandom);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"srcPort")){
			temp = xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				udpConTemp->srcPortRandom = 1;
			else
				udpConTemp->srcPortRandom = 2;
			xmlFree(temp);
			parseUdpStyleSrcPort(doc,cur,udpConTemp->srcPortRandom);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"dataHeader")){
			parseUdpDataHeader(doc,cur);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"data")){
			temp = xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				udpConTemp->dataRandom = 1;
			else
				udpConTemp->dataRandom = 2;
			xmlFree(temp);
			parseUdpData(doc,cur,udpConTemp->dataRandom);
		}
		cur = cur->next;
	}
	return ret;
}
static int parseIcmpStyle(xmlDocPtr doc, xmlNodePtr cur)
{
	int ret=1;
	xmlChar * temp;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"packetLength")){
			temp=xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL){
				icmpConTemp->packetLength=atoi((char *)temp);
				if(icmpConTemp->packetLength>MAXLENGTH)
					icmpConTemp->packetLength=MAXLENGTH;
			}
			else{
				printf("X Error: read xml 'style.packetLength' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"srcIpAddress")){
			temp=xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				icmpConTemp->srcIpAddressRandom = 1;
			else
				icmpConTemp->srcIpAddressRandom = 2;
			xmlFree(temp);
			parseIcmpStyleSrcIp(doc,cur,icmpConTemp->srcIpAddressRandom);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"dataHeader")){
			parseIcmpDataHeader(doc,cur);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"data")){
			temp=xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				icmpConTemp->dataRandom = 1;
			else
				icmpConTemp->dataRandom = 2;
			xmlFree(temp);
			parseIcmpData(doc,cur,icmpConTemp->dataRandom);
		}
		cur = cur->next;
	}
	return ret;
}
static int parseHttpStyle(xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar * temp;
	int ret=1;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"packetLength")){
			temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
			if(temp!=NULL){
				httpConTemp->packetLength=atoi((char *)temp);
				if(httpConTemp->packetLength>MAXLENGTH)
					httpConTemp->packetLength=MAXLENGTH;
			}
			else{
				printf("X Error: read xml 'style.packetLength' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"dataHeader")){
			parseHttpDataHeader(doc,cur);
		}
		else if(!xmlStrcmp(cur->name,(const xmlChar *)"data")){
			temp = xmlGetProp(cur,BAD_CAST("random"));
			if(xmlStrcmp(temp,BAD_CAST("true"))==0)
				httpConTemp->dataRandom = 1;
			else
				httpConTemp->dataRandom = 2;
			xmlFree(temp);
			parseHttpData(doc,cur,httpConTemp->dataRandom);
		}
		cur = cur->next;
	}
	return ret;
}
/********************************************************************************/
/* 转变比例字符为float                                                          */
/********************************************************************************/
static float setPercentageToFloat(char * pertemp)
{
	float result;
	float perNum = atoi(pertemp);
	result = perNum/100;
	return result;
}
/********************************************************************************/
/* 得到所有stylelist属性值                                                      */
/********************************************************************************/
static int parseStyleList (xmlDocPtr doc, xmlNodePtr cur)
{
	int ret=1;
	xmlChar * temp;
	xmlChar * temp_p;
	cur = cur->xmlChildrenNode;
	while(cur!=NULL){
		if(!xmlStrcmp(cur->name,(const xmlChar *)"style")){
			temp = xmlGetProp(cur,BAD_CAST("id"));
			temp_p = xmlGetProp(cur,BAD_CAST("percentage"));
			if(xmlStrcmp(temp,BAD_CAST("synflood"))==0){
				synConTemp = (struct synCon_st *)malloc(sizeof(struct synCon_st));
				memset(synConTemp,0,sizeof(struct synCon_st));
				synConTemp->id = 0;
				if(temp!=NULL)
					synConTemp->id = 1;
				else{
					printf("X Error: read xml 'style.synflood.id' Wrong.\n");
					ret &= 0;
				}
				if(temp_p!=NULL)
					synConTemp->percentage = setPercentageToFloat((char *)temp_p);
				ret &= parseSynStyle(doc,cur);
				ddosc->synStyle = synConTemp;
			}
			else if(xmlStrcmp(temp,BAD_CAST("udpflood"))==0){
				udpConTemp = (struct udpCon_st  *)malloc(sizeof(struct udpCon_st));
				memset(udpConTemp,0,sizeof(struct udpCon_st));
				udpConTemp->id = 0;
				if(temp!=NULL)
					udpConTemp->id = 1;
				else{
					printf("X Error: read xml 'style.udpflood.id' Wrong.\n");
					ret &= 0;
				}
				if(temp_p!=NULL)
					udpConTemp->percentage = setPercentageToFloat((char *)temp_p);
				ret &= parseUdpStyle(doc,cur);
				ddosc->udpStyle = udpConTemp;
			}
			else if(xmlStrcmp(temp,BAD_CAST("icmpflood"))==0){
				icmpConTemp = (struct icmpCon_st  *)malloc(sizeof(struct icmpCon_st));
				memset(icmpConTemp,0,sizeof(struct icmpCon_st));
				icmpConTemp->id = 0;
				if(temp!=NULL)
					icmpConTemp->id = 1;
				else{
					printf("X Error: read xml 'style.icmpflood.id' Wrong.\n");
					ret &= 0;
				}
				if(temp_p!=NULL)
					icmpConTemp->percentage = setPercentageToFloat((char *)temp_p);
				ret &= parseIcmpStyle(doc,cur);
				ddosc->icmpStyle = icmpConTemp;
			}
			else if(xmlStrcmp(temp,BAD_CAST("httpflood"))==0){
				httpConTemp = (struct httpCon_st  *)malloc(sizeof(struct httpCon_st));
				memset(httpConTemp,0,sizeof(struct httpCon_st));
				httpConTemp->id = 0;
				if(temp!=NULL)
					httpConTemp->id = 1;
				else{
					printf("X Error: read xml 'style.httpflood.id' Wrong.\n");
					ret &= 0;
				}
				if(temp_p!=NULL)
					httpConTemp->percentage = setPercentageToFloat((char *)temp_p);
				ret &= parseHttpStyle(doc,cur);
				ddosc->httpStyle = httpConTemp;
			}
			else{//需要添加其他攻击类型在此添加
				printf("X Error: read xml 'style' Wrong.\n");
				ret &= 0;
			}
			xmlFree(temp_p);
			xmlFree(temp);
		}
		cur = cur->next;
	}
	return ret;
}
/********************************************************************************/
/* 从xml文件中得到所有属性值                                                    */
/* 输入:xml文件                                                                 */
/********************************************************************************/
ddosConfig * parseDoc(char * docname)
{
	xmlDocPtr doc;
	xmlNodePtr cur;
	xmlChar * temp;
	int ret=1;
	ddosc = (ddosConfig *)malloc(sizeof(ddosConfig));
	memset(ddosc,0,sizeof(ddosConfig));
	doc = xmlParseFile(docname);
	if(doc==NULL){
		fprintf(stderr,"Document not parsed successfully.\n");
		exit(1);
	}
	cur = xmlDocGetRootElement(doc);
	if(cur==NULL){
		fprintf(stderr,"empty document.\n");
		xmlFreeDoc(doc);
		exit(1);
	}
	//root节点
	if(xmlStrcmp(cur->name,(const xmlChar *)"ddos")){
		fprintf(stderr,"document of the wrong type,root node!=ddos.\n");
		xmlFreeDoc(doc);
		exit(1);
	}
	//root节点mode属性
	temp = xmlGetProp(cur,BAD_CAST("mode"));
	if(temp!=NULL){
		if(xmlStrcmp(temp,BAD_CAST("signal"))==0)
			ddosc->mode = 1;
		else if(xmlStrcmp(temp,BAD_CAST("fixed"))==0)
			ddosc->mode = 2;
		else{
			printf("X Error: read xml 'mode' value Wrong.\n");
			ret &= 0;
		}
		cur = cur->xmlChildrenNode;
		while(cur!=NULL){
			if(!xmlStrcmp(cur->name,(const xmlChar *)"destIp")){
				ret &= parseDestIp(doc,cur);
			}
			else if(!xmlStrcmp(cur->name,(const xmlChar *)"destPort")){
				ret &= parseDestPort(doc,cur);
			}
			else if(!xmlStrcmp(cur->name,(const xmlChar *)"generalMess")){
				ret &= parseGenealMess(doc,cur);
			}
			else if(!xmlStrcmp(cur->name,(const xmlChar *)"styleList")){
				ret &= parseStyleList(doc,cur);
			}
			else if(!xmlStrcmp(cur->name,(const xmlChar *)"getDomainIpTime"))
			{
                temp = xmlNodeListGetString(doc,cur->xmlChildrenNode,1);
                if(temp)
                {
                    ddosc->getip_time = atoi((char *)temp);
                    //printf("--**[%d]\n",ddosc->getip_time);
                }
                else
                    ddosc->src_domain[0]=0;
			}
			cur = cur->next;
		}
	}
	else{
		printf("X Error: read xml 'mode' Wrong.\n");
		xmlFree(temp);
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return NULL;
	}
	if(!ret){
		printf("X Error: xml format wrong.\n");
		xmlFree(temp);
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return NULL;
	}
	xmlFree(temp);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	return ddosc;
}
/********************************************************************************/
/* destroy struct ddosConfig                                                    */
/********************************************************************************/
void destroy_ddosConfig(ddosConfig *ddosc)
{
	if(ddosc){
		if(ddosc->synStyle){
			free(ddosc->synStyle->tcpHeader);
			free(ddosc->synStyle->ipHeader);
			//if(ddosc->synStyle->srcIpls)
			//	free(ddosc->synStyle->srcIpls);
			//if(ddosc->synStyle->srcPortls)
			//	free(ddosc->synStyle->srcPortls);
			if(ddosc->synStyle->datals)
				free(ddosc->synStyle->datals);
			free(ddosc->synStyle);
			ddosc->synStyle = NULL;
		}
		if(ddosc->udpStyle){
			free(ddosc->udpStyle->udpHeader);
			free(ddosc->udpStyle->ipHeader);
			//if(ddosc->udpStyle->srcIpls)
			//	free(ddosc->udpStyle->srcIpls);
			//if(ddosc->udpStyle->srcPortls)
			//	free(ddosc->udpStyle->srcPortls);
			if(ddosc->udpStyle->datals)
				free(ddosc->udpStyle->datals);
			free(ddosc->udpStyle);
			ddosc->udpStyle = NULL;
		}
		if(ddosc->icmpStyle){
			free(ddosc->icmpStyle->icmpHeader);
			free(ddosc->icmpStyle->ipHeader);
			//if(ddosc->icmpStyle->srcIpls)
			//	free(ddosc->icmpStyle->srcIpls);
			if(ddosc->icmpStyle->datals)
				free(ddosc->icmpStyle->datals);
			free(ddosc->icmpStyle);
			ddosc->icmpStyle = NULL;
		}
		if(ddosc->httpStyle){
			if(ddosc->httpStyle->datals)
				free(ddosc->httpStyle->datals);
			free(ddosc->httpStyle);
			ddosc->httpStyle = NULL;
		}
		if(ddosc->ipls)
			free(ddosc->ipls);
		if(ddosc->portls)
			free(ddosc->portls);
		destroy_packetTime(ddosc->packetTimels);

		free(ddosc);
	}
}
