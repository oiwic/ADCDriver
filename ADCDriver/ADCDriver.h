#ifndef ADCDRIVER_H
#define ADCDRIVER_H

#ifdef DLLAPI
#else
#define DLLAPI __declspec(dllimport)
#endif

#define OK 0
#define ERR_NODATA 1
#define ERR_NONETCARD 2
#define ERR_WINPCAP 3
#define ERR_CHANNEL 4
#define ERR_HANDLE 5
#define ERR_OTHER 100

/* ��ADC�豸����Ҫ�ṩĿ��ADC��MAC��ַ��Э�����ͣ��������豸�� */
DLLAPI int OpenADC(int num);
/* �ر�ADC�豸 */
DLLAPI int CloseADC();
/* ��ADCд������ */
DLLAPI int SendData(int len,unsigned char*pData);
/* ��ADC�������� */
DLLAPI int RecvData(int len,int column, unsigned char*pDataI, unsigned char *pDataQ);
/* ��ADC���ؽ�ģ���� */
DLLAPI int RecvDemo(int row,int* pData);
/* ���������б� */
DLLAPI int GetAdapterList(char*list);
/* ���ش�����Ϣ */
DLLAPI int GetErrorMsg(int errorcode,char *strMsg);
/* ��ȡ�汾��Ϣ */
DLLAPI int GetSoftInformation(char *pInformation);
#endif