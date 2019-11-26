/********************************************************************************/
/* 存在于每个攻击机器上的发送攻击结果文件的程序                                 */
/********************************************************************************/
#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "globalData.h"
#include "sendResultFile.h"
/********************************************************************************/
/* 发送攻击结果                                                                 */
/* 返回:1失败;0成功                                                             */
/********************************************************************************/
int sendResult(void)
{
    int sockfd;
	struct sockaddr_in server_addr;
    if( (sockfd=socket(AF_INET,SOCK_STREAM,0))==-1 ){
		fprintf(stderr,"Socket Error:%s\a\n",strerror(errno));
        return 1;
    }
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
	//服务器的IP以及端口号来自配置文件
    if(inet_aton(server_ip,&server_addr.sin_addr) == 0){ 
        printf("X Error: send result file:Server IP Address Error.\n");
        return 1;
    }
    server_addr.sin_port = htons(port_server_sendresult);
    if(connect(sockfd,(struct sockaddr*)&server_addr, sizeof(struct sockaddr)) < 0){
		fprintf(stderr,"Connect Error:%s,%s\a\n",server_ip,strerror(errno));
		return 1;
    }

	char buffer[BUFFER_SIZE];
	FILE * fp = fopen("attackResult.txt","r");
	if(NULL == fp){
		printf("X Error: File attackResult.txt Not Found.\n");
		return 1;
	}
	else{
		bzero(buffer, BUFFER_SIZE);
        int file_block_length = 0;
        while((file_block_length = fread(buffer,sizeof(char),BUFFER_SIZE,fp))>0){
            if(send(sockfd,buffer,file_block_length,0)<0){
				printf("X Error: Send File:attackResult.txt Failed.\n");
                break;
            }
			//printf("%s\n",buffer);
            bzero(buffer, BUFFER_SIZE);
        }
        fclose(fp);
        printf("Action: Result File attackResult.txt send finished.\n");
	}
	close(sockfd);
	return 0;
}
