
#include "pch.h"
#include <iostream>
#include <windows.h>
#include <objbase.h>
#include <oaidl.h>
#include "./detours/detours.h"
#pragma comment(lib,"./detours/detours.lib")
#pragma comment(lib,"rpcrt4.lib")

#include <winternl.h>
#include "common.h"
#include <rpcasync.h>
int DebugPrintfA(LPCSTR ptzFormat, ...)
{
    int iRet = 0;
    va_list vlArgs;
    CHAR tzText[1024];
    va_start(vlArgs, ptzFormat);
    iRet = _vsnprintf_s(tzText, 1024, ptzFormat, vlArgs);
    if (iRet < 0)
    {
        tzText[1023] = '\0';
    }
    strcat_s(tzText, 1024, "\n");
    OutputDebugStringA(tzText);
    va_end(vlArgs);
    return iRet;
}

void PrintLog(CONST char* FuncName)
{
    DebugPrintfA("[TestMacro]%s failed,error=0x08%x\n", FuncName, GetLastError());
}


NTSTATUS
typedef (NTAPI *PtrNtAlpcSendWaitReceivePort)(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_reads_bytes_opt_(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);

PtrNtAlpcSendWaitReceivePort OriginalNtAlpcSendWaitReceivePort = NULL;

NTSTATUS NTAPI MyNtAlpcSendWaitReceivePort(
    _In_ HANDLE PortHandle,
    _In_ ULONG Flags,
    _In_reads_bytes_opt_(SendMessageBuf->u1.s1.TotalLength) PPORT_MESSAGE SendMessageBuf,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
    _Out_writes_bytes_to_opt_(*BufferLength, *BufferLength) PPORT_MESSAGE ReceiveMessage,
    _Inout_opt_ PSIZE_T BufferLength,
    _Inout_opt_ PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
)
{

    // https://docs.microsoft.com/en-us/windows/win32/api/rpcasync/ns-rpcasync-rpc_call_attributes_v2_a


    RPC_CALL_ATTRIBUTES_V2_A CallAttributes;  // this maps to RPC_CALL_ATTRIBUTES_V1
    memset(&CallAttributes, 0, sizeof(CallAttributes));
    CallAttributes.Version = 2;    // maps to 1
    CallAttributes.Flags = 0;
    RPC_STATUS  Status = RpcServerInqCallAttributesA(0, &CallAttributes);
    if (Status == RPC_S_OK)
    {
        WCHAR* wsInterface = NULL;
        StringFromCLSID(CallAttributes.InterfaceUuid, &wsInterface);
        DebugPrintfA("IsClientLocal:%d OpNum=%d InterfaceId:%ws\n",
            CallAttributes.IsClientLocal,
            CallAttributes.OpNum,
            wsInterface
        );
        CoTaskMemFree(wsInterface);
    }
    return OriginalNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessageBuf, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout);
}

// install
void install_hook()
{
    if (OriginalNtAlpcSendWaitReceivePort == NULL)
    {
        HMODULE hModule = LoadLibraryA("ntdll.dll");
        OriginalNtAlpcSendWaitReceivePort = (PtrNtAlpcSendWaitReceivePort)GetProcAddress(hModule, "NtAlpcSendWaitReceivePort");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalNtAlpcSendWaitReceivePort, MyNtAlpcSendWaitReceivePort);
        if (DetourTransactionCommit() == NO_ERROR)
        {
            OutputDebugStringW(L"[install_hook] detoured successfully\n");
        }
    }
}

// uninstall
void uninstall_hook()
{
    
    if (OriginalNtAlpcSendWaitReceivePort)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OriginalNtAlpcSendWaitReceivePort, MyNtAlpcSendWaitReceivePort);
        if (DetourTransactionCommit() == NO_ERROR)
        {
            OutputDebugStringW(L"[install_hook] uninstall detoure successfully\n");
        }
    }
   
}




BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        install_hook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        uninstall_hook();
        break;
    }
    return TRUE;
}

