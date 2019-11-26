/********************************************************************************/
/* 列表数据：链表存储                                                           */
/********************************************************************************/
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <stdlib.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "dataList.h"
/********************************************************************************/
/*结构体dataList*/
dataList * newLink(int numtemp,char *datatemp)
{
	dataList *newOne;
	newOne = (struct dataList_st *)malloc(sizeof(struct dataList_st));
	newOne->num=numtemp;
	newOne->data=datatemp;
	newOne->next=NULL;
	return newOne;
}
/*destory link*/
void destoryLink(dataList * head)
{
	dataList *p,*q;
	p = head;
	while(p!=NULL){
		q = p;
		p=p->next;
		free(q);
	}
	head = NULL;
}

/*list string to list link*/
dataList * get_ls(char * datalsTemp)
{
	char *sep = ",";
	char *needSep = datalsTemp;
	dataList * head = NULL;
	dataList * current,* prev;
	int i=1;
	char * buf = strstr(needSep,sep);
	if(buf==NULL&&needSep[0]!=0){
		current=newLink(i,needSep);
		//printf("%d:%s\n",i,needSep);
		head = current;
	}
	else{
		while(buf!=NULL){
			buf[0]='\0';
			current=newLink(i,needSep);
			//printf("%d:%s\n",i,needSep);
			if(head==NULL){
				head = current;
				prev =head;
			}
			else{
				prev->next = current;
				prev = prev->next;
			}
			i++;
			needSep = buf+1;
			buf = strstr(needSep,sep);
		}
		if(buf==NULL&&needSep[0]!=0){
			current=newLink(i,needSep);
			//printf("%d:%s\n",i,needSep);
			prev->next = current;
			prev = prev->next;
		}
	}
	return head;
}

/*get link length*/
int getLinkLength(dataList * head)
{
	dataList *p;
	p = head;
	int i=0;
	while(p!=NULL){
		i++;
		p=p->next;
	}
	return i;
}

/*output list*/
void outputList(dataList * dataHead)
{
	dataList *p;
	p = dataHead;
	while(p!=NULL){
		printf("num:%d\n",p->num);
		printf("data:%s\n",p->data);
		p = p->next;
	}
}

/*get someone value*/
char * getSomeone(dataList * dataHead,int i)
{
	dataList *p;
	p = dataHead;
	int j;
	for(j=1;j<i;j++)
		p=p->next;
	return p->data;
}
/********************************************************************************/
/********************************************************************************/
datalist_arr * get_ls_arr(char * needSep)
{
	char *sep = ",";
	datalist_arr * dl_arr;
	dl_arr = (datalist_arr *)malloc(sizeof(datalist_arr));
	dl_arr->now_len=0;
	int i=0;
	//printf("-----------xmldate:%s\n",needSep);
	char * buf = strstr(needSep,sep);
	
	if(buf==NULL&&needSep[0]!=0){
		strcpy(dl_arr->data[i],needSep);
		dl_arr->now_len++;
	}
	else{
		while(buf!=NULL&&i<MAX_DATA_NUM)
		{
			buf[0]='\0';
			strcpy(dl_arr->data[i],needSep);
			dl_arr->now_len++;
			i++;
			needSep = buf+1;
			buf = strstr(needSep,sep);
		}
		if(buf==NULL&&needSep[0]!=0&&i<MAX_DATA_NUM){
			strcpy(dl_arr->data[i],needSep);
			dl_arr->now_len++;
		}
	}
	//outputList_arr(dl_arr);
	return dl_arr;
}

int getLinkLength_arr(datalist_arr * head)
{
	return head->now_len;
}
void outputList_arr(datalist_arr * dataHead)
{
	int i=0;
	while(i<dataHead->now_len)
	{
		printf("data:%s\n",dataHead->data[i]);
		i++;
	}
}
char * getSomeone_arr(datalist_arr * dataHead,int i)
{
	//printf("ooooooooo:%s\n",dataHead->data[i]);
	return dataHead->data[i];
}
/********************************************************************************/

int getRandomNumber(int num)
{
	int n;
	n = rand()%num+1;
	return n-1;
}


/*
 * req domain's ip
 * return:
 *      ~NULL  success
 *       NULL  fail
 */
datalist_arr *req_domain_ip(char *domain)
{
    datalist_arr *dl_arr;
	dl_arr = (datalist_arr *)malloc(sizeof(datalist_arr));
	dl_arr->now_len=0;
    int i=0;
	
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(domain, NULL, &hints, &res)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        free(dl_arr);
        return NULL;
    }

    printf("IP for [%s]:", domain);

    for(p = res;p != NULL; p = p->ai_next)
    {
        void *addr;
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) //IPv4
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            printf("  [%s]\n",ipstr);

            strcpy(dl_arr->data[i],ipstr);
		    dl_arr->now_len++;
		    i++;
		    if(i==1)
		        break;
        }
        /*
        else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            printf("  IPv6:[%s]\n",ipstr);
        }
        */
    }
    freeaddrinfo(res); // free the linked list

    //outputList_arr(dl_arr);
	return dl_arr;

}

/*
 * req domain's ip
 * return:
 *        0  ip no change
 *        1  ip change
 *        -1 error
 */
int req_fir_domain_ip(char *ipbuf,char *domain,char *ipold)
{
    int i=0;	
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(domain, NULL, &hints, &res)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    printf("IP for [%s]:", domain);

    for(p = res;p != NULL; p = p->ai_next)
    {
        void *addr;
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) //IPv4
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            printf("  [%s]\n",ipstr);
            
		    i++;
		    if(i==1)
		        break;
        }
        /*
        else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            printf("  IPv6:[%s]\n",ipstr);
        }
        */
    }
    freeaddrinfo(res); // free the linked list
    

    if(strcmp(ipstr,ipold))
    {
        strcpy(ipbuf,ipstr);
        printf("**domain[%s] ip is change:from[%s],to[%s]**\n",
            domain,ipold,ipbuf);
        return 1;
    }
    
	return 0;

}

