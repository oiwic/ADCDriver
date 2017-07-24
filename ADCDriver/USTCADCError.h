#pragma once
// Message ID:USERDEF
// Message text:
// The Error Message is define by user.
#define USERDEF (0x20000000)
// Message ID:SCR_PC
// Message text:
// The Error occur on PC
#define SCR_PC   (0x04000000)
// Message ID:ERRORLEVEL
// Message text:
// Error level
#define ERRORLEVEL (0xC0000000)
// Message ID:FACILITY_WINPCAP
// Message text:
// Position the winpcap error.
#define FACILITY_WINPCAP (0x00010000)
// Define format error code of PC.
#define ERRORCODE(NO) (SCR_PC|ERRORLEVEL|USERDEF|NO)
// Message ID:OK
// Message text:
// No error and return seccessfully
#define OK 0
// Message ID:ERROR_NODATA
// Message text:
// Reveive data timeout, check the net status.
#define ERR_NODATA ERRORCODE(1)
// Message ID:ERR_NONETCARD
// Message text:
// Do not exist netcard. call GetAdatpterList to get a valid list.
#define ERR_NONETCARD ERRORCODE(2)
// Message ID:ERR_WINPCAP
// Message text:
// WinPCap inner error.
#define ERR_WINPCAP ERRORCODE(3)|FACILITY_WINPCAP
// Message ID:ERR_CHANNEL
// Message text:
// Data channel error, may be the protocal error.
#define ERR_CHANNEL ERRORCODE(4)
// Message ID:ERR_HANDLE
// Message text:
// Invalid handle, make sure you have opened the device.
#define ERR_HANDLE ERRORCODE(5)
// Message ID:ERR_OTHER
// Message text:
// Other error, the posibility is less than winning a big lottery.
#define ERR_OTHER ERRORCODE(100)