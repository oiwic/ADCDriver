#ifndef ADCDRIVER_H
#define ADCDRIVER_H

#ifdef DLLAPI
#else
#define DLLAPI __declspec(dllimport)
#endif

#define MAX_ADCNUM 16

/* 打开ADC设备，需要提供目的ADC的MAC地址，协议类型，网卡的设备号 */
DLLAPI int OpenADC(int*id,int num,char *macDst);
/* 关闭ADC设备 */
DLLAPI int CloseADC(int id);
/* 往ADC写入数据 */
DLLAPI int SendData(int id, int len, unsigned char *pData);
/* 从ADC读回数据 */
DLLAPI int RecvData(int id, int len, int column, unsigned char *pDataI, unsigned char *pDataQ);
/* 从ADC读回解模数据 */
DLLAPI int RecvDemo(int id, int row, int* pData);
/* 获取网卡的物理地址 */
DLLAPI int GetMacAddress(int id,int isDst,unsigned char* pMac);
/* 返回错误信息 */
DLLAPI int GetErrorMsg(int id,int errorcode,char *strMsg);
/* 返回网卡列表 */
DLLAPI int GetAdapterList(char*list);
/* 获取版本信息 */
DLLAPI int GetSoftInformation(char *pInformation);
#endif