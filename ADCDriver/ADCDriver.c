#define DLLAPI  __declspec(dllexport)

#include "ADCDriver.h"
#include "pcap.h"
#include <Winsock2.h>

pcap_t *pcapHandle = NULL;									//监听句柄
unsigned char macSrc[6] = {0x34,0x97,0xf6,0x8d,0x41,0x45};	//源mac地址
unsigned char macDst[6] = {0xff,0xff,0xff,0xff,0xff,0xff};	//目的mac地址
unsigned char protocal[2] = {0xaa,0x55};					//协议类型


/* 丢弃一个波形 */
static void ThrowAWave();

DLLAPI int OpenADC(int num)
{
	char   errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fcode;
	pcap_if_t *firstdev;
	pcap_if_t *selectdev;

	/* 查找设备 */
	 pcap_findalldevs(&firstdev,errbuf);
	 selectdev = firstdev;
	 while((num > 1) && selectdev)
	 {
		 selectdev = selectdev->next;
		 num--;
	 }
	 if(selectdev == 0)
	{
		pcap_freealldevs(firstdev);
		return -1;
	 }
	/* 打开网络接口,设置最大帧长度为1500B,超时等待100ms */  
	 pcapHandle=pcap_open_live(selectdev->name,1500,1,100,errbuf);
	/* 设置缓存大小为128MB */
	 pcap_setbuff(pcapHandle,134217728);
	 pcap_setuserbuffer(pcapHandle,134217728);
	/* 设置从内核到用户缓存单次最小拷贝数据大小为1KB */
	 pcap_setmintocopy(pcapHandle,1024);
	/* 设置非阻塞模式 */
	// pcap_setnonblock(pcapHandle,1,errbuf);
	/* 编译过滤器 */
	if(pcap_compile(pcapHandle,&fcode,"ether proto 43605 && not ether src 34.97.f6.8d.41.45",1,0) < 0)
	{
		pcap_freealldevs(firstdev);
        return -1;
	}
	/* 设置过滤器 */
	if(pcap_setfilter(pcapHandle,&fcode) < 0)
	{
		pcap_freealldevs(firstdev);
        return -1;
	}
	pcap_freealldevs(firstdev);
	return 0;
}

DLLAPI int CloseADC()
{
	pcap_close(pcapHandle);
	pcapHandle = NULL;
	return 0;
}

DLLAPI int SendData(int len,unsigned char*pData)
{
	unsigned char *buf = NULL;
	int length = len+14;
	int i;
	buf = (unsigned char*)malloc(length);
	for(i=0;i<length;i++)
	{
		if(i<6)
			*(buf + i) = macDst[i];//Source mac
		else if(i>5 && i < 12)
			*(buf + i) = macSrc[i - 6];//Destination mac
		else if(i>11 && i<14)
			*(buf + i) = protocal[i - 12];//Protocal
		else
			*(buf + i) = *(pData + i - 14);//Data
	}
	if (pcap_sendpacket(pcapHandle, buf, length) != 0)  return -1;
	return 0;
}

DLLAPI int RecvData(int len, int column, unsigned char*pDataI, unsigned char*pDataQ)
{
	unsigned int totalI = 0;
	unsigned int totalQ = 0;
	unsigned int recvcountI = 0;
	unsigned int recvcountQ = 0;
	int res;
	short init = 0;
	unsigned short counter; //frame count
	unsigned short frameCnt;//recv frame count
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	while( totalI < len || totalQ < len)
	{
		res = pcap_next_ex( pcapHandle, &header, &pkt_data);
		if(res > 0)
		{
			if(init == 0)
			{
				init = 1;
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
				else
					return -3;//通道号错误，基本不会出现
			}
			else
			{
				continue;//帧计数错误，这里不返回，将缓存清空后以超时错误返回.
			}
		}
		else
		{ 
			return -1;//超时错误
		}
	}
	return 0;
}

DLLAPI int RecvDemo(int row,int* pData)
{
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	unsigned short counter;
	unsigned short frameCnt;
	int i;
	for(i=0;i<row;i++)
	{
		res = pcap_next_ex( pcapHandle, &header, &pkt_data);
		if(res > 0)
		{		
			if(i == 0)
			{
				counter = ((*(pkt_data + 14))<<8) + (*(pkt_data + 15));	
			}
			frameCnt = ((*(pkt_data + 14))<<8) + (*(pkt_data + 15));
			if(frameCnt == counter)
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
		}
		else
			return -1;
	}
	return 0;
}