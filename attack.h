#ifndef _ATTACK_H_
#define _ATTACK_H_

#define MAXSIZE 1024
//#define getOnePackageTime 70 //组织一个数据包的平均时间，将影响心跳攻击中发包间隔时间的精确，单位微秒

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h>

struct attackM_st
{
	char * attackIp;
	char * attackPort;
	int pthread_id;
};

/********************************************************************************/
/* 开始攻击的主函数                                                             */
/* 输入参数:xml文件的路径                                                       */
/********************************************************************************/
void *startAttack(void * docname);

#endif
