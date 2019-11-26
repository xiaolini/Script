/********************************************************************************/
/* 随机时间获得                                                                 */
/********************************************************************************/
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <stdlib.h>

#include "packetTime.h"
/********************************************************************************/
/* packetTime struct return                                                     */
/********************************************************************************/
packetTime * get_packetTime(
	int packetTimeRandom,
	int packetTimeValue,
	int packetTimeScopeFrom,
	int packetTimeScopeTo,
	int packetTimeMeth)
{
	packetTime * packTimeTemp;
	packTimeTemp = (struct packetTime_st *)malloc(sizeof(struct packetTime_st));
	if(packetTimeRandom==2) { //random is false
		packTimeTemp->packetTimeRandom = 2;
		packTimeTemp->packetTimeValue = packetTimeValue;
	}
	else { //random is true
		packTimeTemp->packetTimeRandom = 1;
		packTimeTemp->packetTimeScopeFrom = packetTimeScopeFrom;
		packTimeTemp->packetTimeScopeTo = packetTimeScopeTo;
		packTimeTemp->packetTimeMeth = packetTimeMeth;
	}
	return packTimeTemp;
}
/********************************************************************************/
/* packetTime destroy                                                           */
/********************************************************************************/
void destroy_packetTime(packetTime * packtime)
{
	if(packtime)
		free(packtime);
}
/********************************************************************************/
/* 输出函数                                                                     */
/********************************************************************************/
void outputPacketTime(packetTime * ptTemp)
{
	printf("packetTimeRandom:%d\n",ptTemp->packetTimeRandom);
	if(ptTemp->packetTimeRandom==1){
		printf("packetTimeScopeFrom:%d\n",ptTemp->packetTimeScopeFrom);
		printf("packetTimeScopeTo:%d\n",ptTemp->packetTimeScopeTo);
		printf("packetTimeMeth:%d\n",ptTemp->packetTimeMeth);
	}
	else
		printf("packetTimeValue:%d\n",ptTemp->packetTimeValue);	

	return;
}
/********************************************************************************/
/* 从指定数目（如n--m中）中均匀随机产生一个数字                                 */
/********************************************************************************/
unsigned int getRandomNumberFT(unsigned int n,unsigned int m)
{
	unsigned int result;
	//srand((unsigned)time(NULL)+rand());
	//n = rand()%(Y-X+1)+X;
	result = rand()%(m-n+1)+n;
	return result;
}
/********************************************************************************/
/* 根据packetTime得到包于包之间的间隔                                           */
/********************************************************************************/
int getSleepTime(packetTime * ptTemp)
{
	int timeTemp;//包间隔时间
	if(ptTemp->packetTimeRandom==1) { //时间随机
		if(ptTemp->packetTimeMeth==1) { //均匀分布
			//printf("from:%d,to:%d\n",ptTemp->packetTimeScopeFrom,ptTemp->packetTimeScopeTo);
			timeTemp = getRandomNumberFT(ptTemp->packetTimeScopeFrom,ptTemp->packetTimeScopeTo);
		}
		else { //非均匀分布
			//
		}
	}
	else { //时间固定
		timeTemp=ptTemp->packetTimeValue;
	}
	//printf("from:%d,to:%d\n",ptTemp->packetTimeScopeFrom,ptTemp->packetTimeScopeTo);
	//printf("getTime:%d\n",timeTemp);
	return timeTemp;
}
