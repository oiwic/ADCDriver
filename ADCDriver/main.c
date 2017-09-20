
//#define DEBUG
//#define DEBUG1
//#define DEBUG2


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

#ifdef DEBUG2
#include "ADCDriver.h"
#include <stdio.h>
int main()
{
	char list[1024]="";
	GetErrorMsg(1,list);
	printf(list);
}
#endif

//#define DEBUG3
#ifdef DEBUG3
#include "USTCADCDriver.h"
#include <stdio.h>
int main()
{
	int id1,id2,id3;
	OpenADC(&id1,1,"00-00-00-00-00-01");
	OpenADC(&id2,2,"00-00-00-00-00-02");
	OpenADC(&id3,3,"00-00-00-00-00-03");
	CloseADC(id1);
	CloseADC(id2);
	CloseADC(id3);
}
#endif

//#define DEBUG4
#ifdef DEBUG4
#include "USTCADCDriver.h"
#include <stdio.h>
int main()
{
	int id1,id2,id3,ret;
	ret = OpenADC(&id1,"68-05-CA-47-45-9A","00-00-00-00-00-01");
	printf("%d",ret);
	ret = OpenADC(&id2,"68-05-CA-47-45-9A","00-00-00-00-00-02");
	printf("%d",ret);
	ret = OpenADC(&id3,"68-05-CA-47-45-9A","00-00-00-00-00-03");
	printf("%d",ret);
	CloseADC(id1);
	CloseADC(id2);
	CloseADC(id3);
}
#endif