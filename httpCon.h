#ifndef _HTTPCON_H_
#define _HTTPCON_H_

#include "dataList.h"

struct httpCon_st 
{
	char id;
	float percentage;
	int packetLength;
	
	//int srcPortRandom;
	//char * srcPortValue;
	//dataList * srcPortls;
	//int srcPortMeth;

	char requestStr[MAXLENGTH];//ÇëÇó±¨ÎÄ
	
	int dataRandom;
	char dataValue[MAXLENGTH];
	datalist_arr * datals;
	int dataMeth;
};

typedef struct httpCon_st httpCon;

#endif
