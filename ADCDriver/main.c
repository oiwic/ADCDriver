
//#define DEBUG
//#define DEBUG1

#ifdef DEBUG
#include "ADCDriver.h"
#include <stdio.h>
int main()
{
	unsigned char forcetrig[] = {0x00,0x01,0xee,0xee,0xee,0xee,0xee,0xee};
	unsigned char datarecvI[2000];
	unsigned char datarecvQ[2000];
	int ret = 0;
	unsigned char sampledepth[] = {0x00,0x12,0x10,0x00};
	if(OpenADC(1)!=0)return 0;
	while(ret == 0)
	{
		//SendData(4,sampledepth);
		//ClearBuff();
		SendData(8,forcetrig);
		ret = RecvData(2000,2000,datarecvI,datarecvQ);
		//printf("%d",ret);
	}
}
#endif

#ifdef DEBUG1
#include "ADCDriver.h"
#include <stdio.h>
int main()
{
	char list[100];
	GetAdapterList(list);
	printf(list);
}
#endif