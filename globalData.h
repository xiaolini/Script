#ifndef _GLOBALDATA_H_
#define _GLOBALDATA_H_

#include <arpa/inet.h>

#define VERSION "2.1.0"//版本号
#define DDOS_NO_CONTROL_ON //不受控制开关
#define DDOS_NO_SEND_IP//不自动向控制端发送IP开关

#define getOnePackageTime 70 //攻击程序中使用:组织一个数据包的平均时间，将影响心跳攻击中发包间隔时间的精确，单位微秒 

#define LENGTH_OF_LISTEN_QUEUE 1//1个控制端
#define BUFFER_SIZE 1024
#define MAX_SIZE 512
#define MAXLENGTH 1486 //最大IP包长1500-14(14Byte以太网头)
#define MAX_PTHREAD_NUM 10 //每次可以开启的最大攻击线程数，超过则按最大处理

#define int_ntoa(x)     inet_ntoa(*((struct in_addr *)&x))
#define int_aton(x)     inet_addr(x)

/********************************************************************************/
/* 全局配置变量                                                                 */
/********************************************************************************/
char server_ip[16];
int port_server;
int port_server_sendip;
int port_server_sendresult;
int wait_time;

#endif

