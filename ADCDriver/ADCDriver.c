#define DLLAPI  __declspec(dllexport)

#include "USTCADCDriver.h"
#include "pcap.h"
#include "USTCADCError.h"
#include <Winsock2.h>
#include <Iphlpapi.h>

pcap_t *pcapHandle[MAX_ADCNUM] = {0};					    //监听句柄
unsigned char macSrc[MAX_ADCNUM][6] = {0};					//源mac地址
unsigned char macDst[MAX_ADCNUM][6] = {0};					//目的mac地址
unsigned char protocal[2] = {0xaa,0x55};					//协议类型

int IsThisMac(char* adaptername,unsigned char *mac,int *isTrue)			//根据适配器名字判断输入mac地址是否为其地址
{
    ULONG ulSize=0;
    PIP_ADAPTER_INFO pInfo = NULL,pNext;
	int ret;
	GetAdaptersInfo(pInfo,&ulSize);     //第一处调用，获取缓冲区大小
    pInfo = (PIP_ADAPTER_INFO)malloc(ulSize);
    ret = GetAdaptersInfo(pInfo,&ulSize);      //第二次调用，获取信息
	if(ret != 0) return ret;
	pNext = pInfo;
    *isTrue = 0;
	while(pNext != NULL){
		if(!strcmp(adaptername,pNext->AdapterName)){
			break;
		}
		pNext = pNext->Next;
	}

	if(pNext != 0)
	{ 
		int j = 0,i = 0;
		for(i = 0; i < 6; i++){
			if(mac[i] == pNext->Address[i]){
				j++;
			}
		}
		if(j == 6){
			*isTrue = 1;
		}
		free(pInfo);
	}
	return 0;
}

int MacStr2Bin(char *strMac, unsigned char *mac)
{
    int i;
    char *start, *end;
    if ((mac == NULL) || (strMac == NULL))
        return -1;
    start = (char *) strMac;
    for (i = 0; i < 6; ++i)
    {
        mac[i] = start ? strtoul (start, &end, 16) : 0;
        if (start)
           start = (*end) ? end + 1 : end;
    }
    return 0;
}

DLLAPI int OpenADC(int *id,char* macSrcPara,char *macDstPara)
{
	struct bpf_program fCode;
	char   errBuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *firstdev;
	pcap_if_t *selectdev;
	char strFilter[1024] = "ether proto 43605 && ether src ";
	char adapterName[1024] = {0};
	unsigned char mac_src[6] = {0};
	unsigned char mac_dst[6] = {0}; 
	int index,ret;
	/* 将字符串转换为数据 */
	MacStr2Bin(macSrcPara,&mac_src[0]);
	MacStr2Bin(macDstPara,&mac_dst[0]);
	/* 检查目的mac地址是否已经被打开，若已经打开则直接返回id */
	for(index = 0; index < MAX_ADCNUM; index++){
		int i = 0, j = 0;
		for(i = 0; i < 6; i++){
			if(mac_dst[i] == macDst[index][i])j++;
		}
		if(j == 6 && pcapHandle[index] != NULL){
			*id = index;
			return OK;
		}
	}
	/* 查找可用空间 */
	 for(index = 0;index < MAX_ADCNUM;index++){
		 if(pcapHandle[index] == NULL){
			 break;
		 }
	 }
	 if(index == MAX_ADCNUM){
		 return ERR_TOOMUCHOBJ;
	 }
	 /* 查找适配器 */
	 ret = pcap_findalldevs(&firstdev,errBuf);
	 if(ret != 0){
		 return ret;
	 }
	 selectdev = firstdev;
	 while(selectdev){
		 int isTrue;
		 strcpy_s(adapterName,1024,selectdev->name+12);	
		 ret = IsThisMac(&adapterName[0],&mac_src[0],&isTrue);
		 if(ret == 0 && isTrue == 1){
			 break;
		 }
		 selectdev = selectdev->next;
	 }
	 if(selectdev == NULL){
		pcap_freealldevs(firstdev);
		return ERR_NONETCARD;
	 }
	/* 打开网络接口,设置最大帧长度为1500B,超时等待100ms */  
	 pcapHandle[index] = pcap_open_live(selectdev->name,1500,1,100,errBuf);
	/* 设置缓存大小为128MB */
	 ret = pcap_setbuff(pcapHandle[index],134217728);
	 if(ret != 0){
		 return ret;
	 }
	 ret = pcap_setuserbuffer(pcapHandle[index],134217728);
	 if(ret != 0){
		 return ret;
	 }
	/* 设置从内核到用户缓存单次最小拷贝数据大小为1KB */
	 ret = pcap_setmintocopy(pcapHandle[index],1024);
	 if(ret != 0){
		 return ret;
	 }
	/* 编译过滤器 主机mac地址是固定的，需要过滤掉源是这个地址的数据*/
	strcat_s(strFilter,1024,macDstPara);
	if(pcap_compile(pcapHandle[index],&fCode,strFilter,1,0) < 0){
		pcap_freealldevs(firstdev);
        return ERR_COMPILEFILTER;
	}
	/* 设置过滤器 */
	if(pcap_setfilter(pcapHandle[index],&fCode) < 0){
		pcap_freealldevs(firstdev);
        return ERR_OTHER;
	}
	pcap_freealldevs(firstdev);
	*id = index;
	memcpy(&macSrc[index][0],&mac_src[0],6);
	memcpy(&macDst[index][0],&mac_dst[0],6);
	return OK;
}

DLLAPI int CloseADC(int id)
{
	if(pcapHandle[id] != NULL)
	{
		pcap_close(pcapHandle[id]);
		pcapHandle[id] = NULL;
		memset(&macSrc[id][0],0,6);
		memset(&macDst[id][0],0,6);
	}
	return OK;
}

DLLAPI int SendData(int id,int len,unsigned char*pData)
{
	unsigned char *buf = NULL;
	int length = len+14;
	int i;
	if(id >= MAX_ADCNUM || id < 0) return ERR_HANDLE;
	if(pcapHandle[id] == NULL) return ERR_HANDLE;
	buf = (unsigned char*)malloc(length);
	for(i=0;i<length;i++)
	{
		if(i<6)
			*(buf + i) = macDst[id][i];//Destination mac
		else if(i>5 && i < 12)
			*(buf + i) = macSrc[id][i - 6];//Source mac
		else if(i>11 && i<14)
			*(buf + i) = protocal[i - 12];//Protocal
		else
			*(buf + i) = *(pData + i - 14);//Data
	}
	if (pcap_sendpacket(pcapHandle[id], buf, length) != 0)  return ERR_WINPCAP;
	return OK;
}

DLLAPI int RecvData(int id,int row, int column, unsigned char*pDataI, unsigned char*pDataQ)
{
	unsigned int totalI = 0;
	unsigned int totalQ = 0;
	unsigned int recvcountI = 0;
	unsigned int recvcountQ = 0;
	unsigned int len = row*column;
	int ret;
	short bInit = 0;
	unsigned short counter; //frame count
	unsigned short frameCnt;//recv frame count
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	if(id >= MAX_ADCNUM || id < 0) return ERR_HANDLE;
	if(pcapHandle[id] == NULL) return ERR_HANDLE;
	while( totalI < len || totalQ < len)
	{
		ret = pcap_next_ex( pcapHandle[id], &header, &pkt_data);
		if(ret > 0)
		{
			if(bInit == 0)
			{
				bInit = 1;
				counter = ((*(pkt_data + 14))<<8) + (*(pkt_data + 15));	
			}
			frameCnt = ((*(pkt_data + 14))<<8) + (*(pkt_data + 15));	
			if(frameCnt == counter)
			{
				if(1 == *(pkt_data+16) && totalQ<len)//channel Q
				{
					if(recvcountQ + header->caplen-17 < column)//if recv length is less than column
					{
						memcpy(pDataQ+totalQ+recvcountQ,pkt_data+17,header->caplen-17);
						recvcountQ += (header->caplen-17);
					}
					else//if recv length is more than column
					{
						memcpy(pDataQ+totalQ+recvcountQ,pkt_data+17,column - recvcountQ);
						recvcountQ += (column - recvcountQ);
						totalQ += recvcountQ;
						recvcountQ = 0;
					}
					counter++;
				}
				else if(16 == *(pkt_data+16) && totalI<len)//channel I
				{
					if(recvcountI + header->caplen-17 < column)
					{
						memcpy(pDataI+totalI+recvcountI,pkt_data+17,header->caplen-17);
						recvcountI += (header->caplen-17);
					}
					else//if recv length is more than len
					{
						memcpy(pDataI + totalI + recvcountI,pkt_data+17,column - recvcountI);
						recvcountI += (column - recvcountI);
						totalI += recvcountI;
						recvcountI = 0;
					}
					counter++;
				}
				else	return ERR_CHANNEL;
			}
			else continue;//帧计数错误，这里不返回，将缓存清空后以超时错误返回.
		}
		else	return ERR_NODATA;//超时错误
	}
	return OK;
}

DLLAPI int RecvDemo(int id,int row,int* pData)
{
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	unsigned short counter;
	unsigned short frameCnt;
	int i;
	if(id >= MAX_ADCNUM || id < 0) return ERR_HANDLE;
	if(pcapHandle[id] == NULL) return ERR_HANDLE;
	for(i=0;i<row;i++)
	{
		res = pcap_next_ex( pcapHandle[id], &header, &pkt_data);
		if(res > 0)
		{		
			if(i == 0)
			{
				counter = ((*(pkt_data + 14))<<8) + (*(pkt_data + 15));	
			}
			frameCnt = ((*(pkt_data + 14))<<8) + (*(pkt_data + 15));
			if(frameCnt == counter)
			{
				if(34 == *(pkt_data+16))
				{
					unsigned char data[8];
					data[0] = *(pkt_data+3+17);
					data[1] = *(pkt_data+2+17);
					data[2] = *(pkt_data+1+17);
					data[3] = *(pkt_data+0+17);
					data[4] = *(pkt_data+7+17);
					data[5] = *(pkt_data+6+17);
					data[6] = *(pkt_data+5+17);
					data[7] = *(pkt_data+4+17);
					memcpy(pData+2*i,data,8);
					counter++;
				}
				else	return ERR_CHANNEL;
			}
		}
		else	return ERR_NODATA;
	}
	return OK;
}

DLLAPI int GetSoftInformation(char *pInformation)
{
	char *strInfo = "USTCADC Driver v2.1 @2017/09/20";
	memcpy(pInformation,strInfo,strlen(strInfo));
	pInformation[strlen(strInfo)] = 0;
	return OK;
}

DLLAPI int GetErrorMsg(int id,int errorcode ,char * strMsg)
{
	if(errorcode & USERDEF)
	{
		char *prefix = "USTCDACDRIVER API failed: ";
		char *info;
		if(errorcode & FACILITY_WINPCAP)
		{
			if(id >= MAX_ADCNUM || id < 0) return ERR_HANDLE;
			if(pcapHandle[id] == NULL) return ERR_HANDLE;
			info = pcap_geterr(pcapHandle[id]);
		}
		else
		{
			switch(errorcode)
			{
				case ERR_NODATA:info = "Receive data timeout, check the net status.\n";break;
				case ERR_NONETCARD: info = "Do not exist netcard. call GetAdatpterList to get a valid list.\n";break;
				case ERR_CHANNEL: info = "Data channel error, may be the protocal error.\n";break;
				case ERR_OTHER: info = "Other error, the posibility is less than winning a big lottery.\n";break;
				case ERR_HANDLE: info = "Invalid handle, make sure you have opened the device.\n";break;
				case ERR_TOOMUCHOBJ:info = "You have been opened too much ADCs.\n";break;
				case ERR_COMPILEFILTER:info = "Compile filter error, you may check you dstination mac address.\n";break;
				default: info = "Are you sure this was caused by USTCADCDriver?\n";
			}
		}
		strcpy_s(strMsg,1024,prefix);
		strcat_s(strMsg,1024,info);
		return OK;
	}
	else
	{
		HLOCAL hlocal = NULL;
		DWORD dwSystemLocale = MAKELANGID( LANG_NEUTRAL, SUBLANG_NEUTRAL );  
		BOOL bOk = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL,errorcode,dwSystemLocale,(PTSTR)&hlocal, 0, NULL );
		if(bOk && hlocal != NULL)
		{
			char *prefix = "Windows API failed: ";
			strcpy_s(strMsg,1024,prefix);
			strcat_s(strMsg,1024,hlocal);
			LocalFree(hlocal);
			return OK;
		}
		return ERR_OTHER;
	}
}

DLLAPI int GetMacAddress(int id,int isDst,unsigned char* pMac)
{
	if(id >= MAX_ADCNUM || id < 0) return ERR_HANDLE;
	if(pcapHandle[id] != NULL)
	{
		if(isDst == 0)
			memcpy(pMac,&macSrc[id][0],6);
		else
			memcpy(pMac,&macDst[id][0],6);
		return OK;
	}
	return ERR_HANDLE;
}
