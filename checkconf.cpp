#include "stdafx.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#include <stdlib.h>

#include <string>
using namespace std;

#include <Wininet.h>
#pragma comment(lib, "Wininet.lib")

#include "Wlanapi.h"
#pragma comment(lib, "Wlanapi.lib")

#include   "iphlpapi.h"  
#pragma   comment(lib, "iphlpapi.lib   ")  

#include <shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

#pragma comment(lib,"Advapi32.lib")

BOOL GetPhyDriveSerial(LPTSTR pModelNo, LPTSTR pSerialNo);
void ToLittleEndian(PUSHORT pWords, int nFirstIndex, int nLastIndex, LPTSTR pBuf);
void TrimStart(LPTSTR pBuf);
BOOL GetMacByCmd(char *lpszMac);
BOOL GetMacAddress();
BOOL GetPassStrategyByCmd();
BOOL CheckScreensavers();

int PassLen;
int PassComplex;
int main()
{
	TCHAR szModelNo[48], szSerialNo[24];

	const int MAX_BUFFER_LEN = 128;  
	WCHAR szBuffer[MAX_BUFFER_LEN];  
    DWORD dwNameLen; 
	DWORD pdwNegotiatedVersion;
	HANDLE phClientHandle;
	PWLAN_INTERFACE_INFO_LIST wiiList;

  
	printf("<<>> CHK CONFIG TOOL 1.0.0 <<>>\n");
	printf(";made by zzt 2014/10/13\n");
	printf(";requirement:  win7/vista need run at administrator level\n");
	printf("\n");
	//Get ComputerName and userName
	printf("##基本信息：\n");
    dwNameLen = MAX_BUFFER_LEN;  
	if (!GetComputerName(szBuffer, &dwNameLen))
        printf("Get ComputerName Error  %d\n", GetLastError());  
    else
	{
		printf("@计算机名:  ");
		wprintf(szBuffer);
		printf("\n");
	}
  
    dwNameLen = MAX_BUFFER_LEN;  
    if (!GetUserName(LPWSTR(szBuffer), &dwNameLen))  
        printf("@Get UserNmae Error  %d\n", GetLastError());  
    else  
	{
		printf("@用户名:  ");
		wprintf(szBuffer);
        printf("\n");
	}

	//Get Hard Driver Serial No need administrator 
    if(GetPhyDriveSerial(szModelNo, szSerialNo))
    {
		_tprintf(_T("@Model No:  %s\n"), szModelNo);
        TrimStart(szSerialNo);
		_tprintf(_T("@Serial No:  %s\n"), szSerialNo);
    }
    else
    {
        _tprintf(_T("@Get Hard Driver Serial No Failed.\n"));
    }


	//Get MAC information
	printf("@MAC:  \n");
	if(!GetMacAddress())
	{
		printf("Get MacInfo Error\n");
	}
	
	//check wifi yes or no 
	printf("\n##CHECK WIFI\n");
	WlanOpenHandle (1,NULL,&pdwNegotiatedVersion,&phClientHandle);
	WlanEnumInterfaces(phClientHandle,NULL,&wiiList);
	if(wiiList->dwNumberOfItems > 0)
	{
		printf("@WIFI检查:  不通过 \n");
		printf("原因: \n");
		printf("    @发现无线网卡\n");
		printf("    @WIFI 描述:  ");
		wprintf(wiiList->InterfaceInfo->strInterfaceDescription);
		printf("\n");
	}
	else
	{
		printf("@WIFIWIFI检查:  通过 \n");
	}

	//check password strategy yes or no
	printf("\n##CHECK PASSWORD STRATEGY \n");
	if(GetPassStrategyByCmd())
	{
		if(PassLen == 0)
			printf("@密码长度策略:  (未设置)不通过 \n");
		else if(PassLen > 0 )
			printf("@密码长度:  (%d位)通过\n",PassLen);

		if(PassComplex ==0)
			printf("@密码复杂度策略:  （未设置）不通过 \n");
		else if(PassComplex > 0)
			printf("@密码复杂度:  (开启)通过 \n");
	}
	else
		printf("Check Pass Strategy failed\n");

	//Check Screensavers yes or no
	printf("\n##CHECK SCREENSAVERS PASSWORD  \n");
	if(CheckScreensavers()==1)
		printf("@屏保密码:  (已开启)通过\n");
	else
		printf("@屏保密码:  (未设置)不通过\n");

	//Check Internet Connection yes or no
	printf("\n##CHECK INTERNET CONNECTION  \n");
	if(InternetCheckConnection(_T("http://www.baidu.com"),FLAG_ICC_FORCE_CONNECTION, 0))
		printf("@internet连接:  (可以连接外网)不通过\n");
	else if(GetLastError()==ERROR_NOT_CONNECTED)
		printf("@Check Internet Connection failed\n");
	else
		printf("@internet连接: (不能连接外网)通过\n");


    getchar();
    return 0;
}

//
// Model Number: 40 ASCII Chars
// SerialNumber: 20 ASCII Chars
//
BOOL GetPhyDriveSerial(LPTSTR pModelNo, LPTSTR pSerialNo)
{
    //-1是因为 SENDCMDOUTPARAMS 的结尾是 BYTE bBuffer[1];
    BYTE IdentifyResult[sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1];
    DWORD dwBytesReturned;
    GETVERSIONINPARAMS get_version;
    SENDCMDINPARAMS send_cmd = { 0 };

    HANDLE hFile = CreateFile(_T("\\\\.\\PHYSICALDRIVE0"), GENERIC_READ | GENERIC_WRITE,    
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    //get version
    DeviceIoControl(hFile, SMART_GET_VERSION, NULL, 0,
        &get_version, sizeof(get_version), &dwBytesReturned, NULL);

    //identify device
    send_cmd.irDriveRegs.bCommandReg = (get_version.bIDEDeviceMap & 0x10)? ATAPI_ID_CMD : ID_CMD;
    DeviceIoControl(hFile, SMART_RCV_DRIVE_DATA, &send_cmd, sizeof(SENDCMDINPARAMS) - 1,
        IdentifyResult, sizeof(IdentifyResult), &dwBytesReturned, NULL);
    CloseHandle(hFile);

    //adjust the byte order
    PUSHORT pWords = (USHORT*)(((SENDCMDOUTPARAMS*)IdentifyResult)->bBuffer);
    ToLittleEndian(pWords, 27, 46, pModelNo);
    ToLittleEndian(pWords, 10, 19, pSerialNo);
    return TRUE;
}

//把WORD数组调整字节序为little-endian，并滤除字符串结尾的空格。
void ToLittleEndian(PUSHORT pWords, int nFirstIndex, int nLastIndex, LPTSTR pBuf)
{
    int index;
    LPTSTR pDest = pBuf;
    for(index = nFirstIndex; index <= nLastIndex; ++index)
    {
        pDest[0] = pWords[index] >> 8;
        pDest[1] = pWords[index] & 0xFF;
        pDest += 2;
    }    
    *pDest = 0;
    
    //trim space at the endof string; 0x20: _T(' ')
    --pDest;
    while(*pDest == 0x20)
    {
        *pDest = 0;
        --pDest;
    }
}

//滤除字符串起始位置的空格
void TrimStart(LPTSTR pBuf)
{
    if(*pBuf != 0x20)
        return;

    LPTSTR pDest = pBuf;
    LPTSTR pSrc = pBuf + 1;
    while(*pSrc == 0x20)
        ++pSrc;

    while(*pSrc)
    {
        *pDest = *pSrc;
        ++pDest;
        ++pSrc;
    }
    *pDest = 0;
}

BOOL GetPassStrategyByCmd()
{
	BOOL bret; 
	const long MAX_COMMAND_SIZE = 10000;
	int breakout = 0;

	WCHAR szFetCmd[] = L"secedit /export /CFG c:\\ps.ini /quiet";


	//控制命令行窗口信息
	STARTUPINFO si; 
	//返回进程信息
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO); 
	GetStartupInfo(&si);  
	si.wShowWindow = SW_HIDE; //隐藏命令行窗口

	//检查是否已经存在该文件，如存在则删除
	if(PathFileExists(_T("c:\\ps.ini"))){
		DeleteFile(_T("c:\\ps.ini"));
	}
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	//创建获取命令行进程
	bret = CreateProcess (NULL, szFetCmd , NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi ); 
	if (bret) 
	{
		WaitForSingleObject (pi.hProcess, INFINITE);//等待进程结束
		if(PathFileExists(_T("c:\\ps.ini")))
		{
			PassLen = GetPrivateProfileInt(_T("System Access"),_T("MinimumPasswordLength"),-1,_T("c:\\ps.ini"));
			PassComplex = GetPrivateProfileInt(_T("System Access"),_T("PasswordComplexity"),-1,_T("c:\\ps.ini"));		
			return TRUE;
		}
		else
			return FALSE;
	}
	else
		return FALSE;
}

BOOL GetMacByCmd(char *lpszMac)
{
	//初始化返回MAC地址缓冲区
	memset(lpszMac, 0x00, sizeof(lpszMac));
	BOOL bret; 
	SECURITY_ATTRIBUTES sa; 
	HANDLE hReadPipe,hWritePipe;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
	sa.lpSecurityDescriptor = NULL; 
	sa.bInheritHandle = TRUE; 
	const long MAX_COMMAND_SIZE = 10000;
	const string str4Search = "Physical Address. . . . . . . . . : ";
	WCHAR szFetCmd[] = L"ipconfig /all";

	
	//创建管道
	bret = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
	if(!bret)
	{
		return FALSE;
	}
	//控制命令行窗口信息
	STARTUPINFO si; 
	//返回进程信息
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO); 
	GetStartupInfo(&si); 
	si.hStdError = hWritePipe; 
	si.hStdOutput = hWritePipe; 
	si.wShowWindow = SW_HIDE; //隐藏命令行窗口
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	//创建获取命令行进程
	bret = CreateProcess (NULL, szFetCmd , NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi ); 
 
	char szBuffer[MAX_COMMAND_SIZE+1]; //放置命令行输出缓冲区
	string strBuffer;
	if (bret) 
	{ 
//		WaitForSingleObject (pi.hProcess, INFINITE); 
		unsigned long count;
		CloseHandle(hWritePipe);
		memset(szBuffer, 0x00, sizeof(szBuffer));
		bret  =  ReadFile(hReadPipe,  szBuffer,  MAX_COMMAND_SIZE,  &count,  0);
		if(!bret)
		{
			//关闭所有的句柄
			CloseHandle(hWritePipe);
			CloseHandle(pi.hProcess); 
			CloseHandle(pi.hThread); 
			CloseHandle(hReadPipe);
			return FALSE;
		}
		else
		{
			strBuffer = szBuffer;
			long ipos;
			ipos = strBuffer.find(str4Search);
			//提取MAC地址串
			strBuffer = strBuffer.substr(ipos+str4Search.length());
			ipos = strBuffer.find("/n");
			strBuffer = strBuffer.substr(0, ipos);

			memset(szBuffer, 0x00, sizeof(szBuffer));
			strcpy_s(szBuffer, strBuffer.c_str());
			//去掉中间的“00-50-EB-0F-27-82”中间的'-'得到0050EB0F2782
			int j = 0;
			for(int i=0; i < (int)strlen(szBuffer); i++)
			{
				if(szBuffer[i] != '-')
				{
					lpszMac[j] = szBuffer[i];
					j++;
				}
			}
		}
  
	}

	//关闭所有的句柄
	CloseHandle(hWritePipe);
	CloseHandle(pi.hProcess); 
	CloseHandle(pi.hThread); 
	CloseHandle(hReadPipe);
	return TRUE;
}

BOOL GetMacAddress()  
{  
	PIP_ADAPTER_INFO pAdapterInfo;  
	PIP_ADAPTER_INFO pAdapter; 
	DWORD AdapterInfoSize;  
	TCHAR szMac[32] = {0};  
	DWORD Err;    
	AdapterInfoSize = 0;  
	Err = GetAdaptersInfo(NULL,&AdapterInfoSize);  
	if((Err != 0)&&(Err != ERROR_BUFFER_OVERFLOW)){   
		return FALSE;  
	}  
	//   分配网卡信息内存  
	pAdapterInfo = (PIP_ADAPTER_INFO)GlobalAlloc(GPTR,AdapterInfoSize);  
	if(pAdapterInfo == NULL){  
			return FALSE;  
	}    
	if(GetAdaptersInfo(pAdapterInfo, &AdapterInfoSize) != 0 ){  
		GlobalFree(pAdapterInfo);  
		return FALSE;  
	}   

	pAdapter = pAdapterInfo;
	do{
		printf("    描述: %s\n",pAdapter->Description);
		printf("    地址: %02X-%02X-%02X-%02X-%02X-%02X\n",
			pAdapter->Address[0],
			pAdapter->Address[1],
			pAdapter->Address[2],
			pAdapter->Address[3],
			pAdapter->Address[4],
			pAdapter->Address[5]
			);
		pAdapter = pAdapter->Next;
	}while(pAdapter != NULL);

	GlobalFree(pAdapterInfo); 
	GlobalFree(pAdapter);
	return   TRUE;  
}

/*
ret = 0 #Screensavers pass not set
ret = 1 #Screensavers pass set
ret = 2 #Open Failed
ret = 3 #Query Failed
*/
int CheckScreensavers()
{
	WCHAR regPath[] = L"Control Panel\\Desktop";
	int ret=0;
	LPBYTE Buffer = new BYTE[1];
	DWORD dwType = REG_SZ;
	DWORD dwSize = sizeof(Buffer);

	HKEY hKey;

	if(RegOpenKeyEx(HKEY_CURRENT_USER, regPath,0,KEY_READ, &hKey) == ERROR_SUCCESS )
	{
		if(RegQueryValueEx(hKey,_T("ScreenSaverIsSecure"), 0, &dwType ,Buffer, &dwSize) == ERROR_SUCCESS )
		{
//			printf("sccesus\n");
			if(!strcmp((char*)Buffer,"1"))
//			if(Buffer == (LPBYTE)'1')
				ret = 1;
			else
				ret = 0;
		
		}
		else{
			printf("@Query Value Failed\n");
			ret = 3;
		}
	}
	else{
		printf("@Open Reg Failed\n");
		ret = 2;
	}
	return ret;
}