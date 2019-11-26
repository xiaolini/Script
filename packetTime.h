#ifndef _PACKETTIME_H_
#define _PACKETTIME_H_

struct packetTime_st 
{
	int packetTimeRandom;
	int packetTimeValue;
	int packetTimeScopeFrom;
	int packetTimeScopeTo;
	int packetTimeMeth;
};

typedef struct packetTime_st packetTime;

/********************************************************************************/
/* 写间隔配置到结构体packetTime_st                                              */
/* 输入参数:间隔配置                                                            */
/* 输出:间隔配置结构体packetTime_st头指针                                       */
/********************************************************************************/
packetTime * get_packetTime(
	int packetTimeRandom,
	int packetTimeValue,
	int packetTimeScopeFrom,
	int packetTimeScopeTo,
	int packetTimeMeth);
/********************************************************************************/
/* 输出间隔配置                                                                 */
/* 输入参数:间隔配置结构体packetTime_st                                         */
/********************************************************************************/
void outputPacketTime(packetTime * ptTemp);
/********************************************************************************/
/* 得到间隔时间                                                                 */
/* 输入参数:间隔配置结构体packetTime_st                                         */
/* 输出:间隔时间                                                                */
/********************************************************************************/
int getSleepTime(packetTime * ptTemp);
/********************************************************************************/
/* 释放间隔时间                                                                 */
/* 输入:间隔配置结构体packetTime_st                                             */
/********************************************************************************/
void destroy_packetTime(packetTime * packtime);

/********************************************************************************/
/* 从指定数目（如n--m中）中均匀随机产生一个数字                                 */
/********************************************************************************/
unsigned int getRandomNumberFT(unsigned int n,unsigned int m);

#endif
