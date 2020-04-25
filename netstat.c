#include <Windows.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "WS2_32.lib")

#define MODNAME_LENGTH 64

void get_tcp_info(void)
{
    PMIB_TCPTABLE_OWNER_MODULE pTcpTable   = NULL;
    PTCPIP_OWNER_MODULE_BASIC_INFO modInfo = NULL;
    DWORD dwSize = 0;

    char szLocalAddr[16]  = {0};
    char szRemoteAddr[16] = {0};
    char state[16]        = {0};
    
    char localInfo[32]  = {0};
    char remoteInfo[32] = {0};
    char modName[MODNAME_LENGTH]  = {0};

    struct in_addr IpAddr;
    int i;
    int charcount;

    GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
    pTcpTable = (PMIB_TCPTABLE_OWNER_MODULE) calloc(dwSize,1);
    if (NULL == pTcpTable)
    {
        printf("Error allocating memory\n");
        return;
    }
    
    if (NO_ERROR != GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0))
    {
        printf("\tGetTcpTable failed\n");
        free(pTcpTable);
        return;
    }
        
    printf(" %d rows\n", (int) pTcpTable->dwNumEntries);
    printf(" Proto  Local Address            Foreign Address          State         PID            Module Name\n");
    
    for (i = 0; i < (int) pTcpTable->dwNumEntries; i++) {
        IpAddr.S_un.S_addr = (u_long) pTcpTable->table[i].dwLocalAddr;
        strcpy_s(szLocalAddr,  sizeof (szLocalAddr),  inet_ntoa(IpAddr));
        IpAddr.S_un.S_addr = (u_long) pTcpTable->table[i].dwRemoteAddr;
        strcpy_s(szRemoteAddr, sizeof (szRemoteAddr), inet_ntoa(IpAddr));

        switch (pTcpTable->table[i].dwState) {
        case MIB_TCP_STATE_CLOSED:
            strcpy_s(state, 16,"CLOSED");
            break;
        case MIB_TCP_STATE_LISTEN:
            strcpy_s(state, 16,"LISTEN");
            break;
        case MIB_TCP_STATE_SYN_SENT:
            strcpy_s(state, 16,"SYN-SENT");
            break;
        case MIB_TCP_STATE_SYN_RCVD:
            strcpy_s(state, 16,"SYN-RECEIVED");
            break;
        case MIB_TCP_STATE_ESTAB:
            strcpy_s(state, 16,"ESTABLISHED");
            break;
        case MIB_TCP_STATE_FIN_WAIT1:
            strcpy_s(state, 16,"FIN-WAIT-1");
            break;
        case MIB_TCP_STATE_FIN_WAIT2:
            strcpy_s(state, 16,"FIN-WAIT-2");
            break;
        case MIB_TCP_STATE_CLOSE_WAIT:
            strcpy_s(state, 16,"CLOSE-WAIT");
            break;
        case MIB_TCP_STATE_CLOSING:
            strcpy_s(state, 16,"CLOSING");
            break;
        case MIB_TCP_STATE_LAST_ACK:
            strcpy_s(state, 16,"LAST-ACK");
            break;
        case MIB_TCP_STATE_TIME_WAIT:
            strcpy_s(state, 16,"TIME-WAIT");
            break;
        case MIB_TCP_STATE_DELETE_TCB:
            strcpy_s(state, 16,"DELETE-TCB");
            break;
        default:
            strcpy_s(state, 16,"UNKNOWN");
            break;
        }

        memset(modName, 0, MODNAME_LENGTH);
        dwSize = 0;
        
        GetOwnerModuleFromTcpEntry(&(pTcpTable->table[i]), TCPIP_OWNER_MODULE_INFO_BASIC, NULL, &dwSize);
        modInfo = (PTCPIP_OWNER_MODULE_BASIC_INFO)calloc(dwSize, 1);
        if (NULL != modInfo)
        {
            if (NO_ERROR == GetOwnerModuleFromTcpEntry(&(pTcpTable->table[i]), TCPIP_OWNER_MODULE_INFO_BASIC, modInfo, &dwSize))
            {
                wcstombs_s(&charcount, modName, MODNAME_LENGTH, modInfo->pModuleName, MODNAME_LENGTH);
            }
        }
        else
        {
            printf("Error allocating memory\n");
        }
        if (modInfo) { free(modInfo); modInfo = NULL; }
        
        sprintf_s(localInfo, 32, "%s:%d",  szLocalAddr, ntohs((u_short)pTcpTable->table[i].dwLocalPort));
        sprintf_s(remoteInfo, 32, "%s:%d", szRemoteAddr,ntohs((u_short)pTcpTable->table[i].dwRemotePort));
        printf(" TCP    %-23s  %-23s  %-12s  %-12d   %s\n",localInfo,remoteInfo,state,pTcpTable->table[i].dwOwningPid, modName);
    }
    
    if (pTcpTable) { free(pTcpTable); pTcpTable = NULL; }
    if (modInfo)   { free(modInfo);   modInfo   = NULL; }

    return;
}

void get_udp_info(void)
{
    PMIB_UDPTABLE_OWNER_MODULE pUdpTable   = NULL;
    PTCPIP_OWNER_MODULE_BASIC_INFO modInfo = NULL;
    
    DWORD dwSize = 0;

    char szLocalAddr[16]  = {0};
    char localInfo[32]    = {0};
    char modName[MODNAME_LENGTH]  = {0};

    struct in_addr IpAddr;
    int i;
    int charcount;

    GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
    pUdpTable = (PMIB_UDPTABLE_OWNER_MODULE) calloc(dwSize,1);
    if (NULL == pUdpTable)
    {
        printf("Error allocating memory\n");
        return;
    }
    
    if (NO_ERROR != GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0))
    {
        printf("\tGetUdpTable failed\n");
        free(pUdpTable);
        return;
    }
       
    printf(" %d rows\n", (int)pUdpTable->dwNumEntries);
    printf(" Proto  Local Address            Foreign Address          State         PID            Module Name\n");
    
    for (i = 0; i < (int) pUdpTable->dwNumEntries; i++) {
        IpAddr.S_un.S_addr = (u_long) pUdpTable->table[i].dwLocalAddr;
        strcpy_s(szLocalAddr,  sizeof (szLocalAddr),  inet_ntoa(IpAddr));

        memset(modName, 0, MODNAME_LENGTH);
        dwSize = 0;
        
        GetOwnerModuleFromUdpEntry(&(pUdpTable->table[i]), TCPIP_OWNER_MODULE_INFO_BASIC, NULL, &dwSize);
        modInfo = (PTCPIP_OWNER_MODULE_BASIC_INFO)calloc(dwSize, 1);
        if (NULL != modInfo)
        {
            if (NO_ERROR == GetOwnerModuleFromUdpEntry(&(pUdpTable->table[i]), TCPIP_OWNER_MODULE_INFO_BASIC, modInfo, &dwSize))
            {
                wcstombs_s(&charcount, modName, MODNAME_LENGTH, modInfo->pModuleName, MODNAME_LENGTH);
            }
        }
        else
        {
            printf("Error allocating memory\n");
        }
        if (modInfo) { free(modInfo); modInfo = NULL; }
        
        sprintf_s(localInfo, 32, "%s:%d", szLocalAddr, ntohs((u_short)pUdpTable->table[i].dwLocalPort));
        printf(" UDP    %-23s  %-23s  %-12s  %-12d   %s\n",localInfo,"*:*"," ",pUdpTable->table[i].dwOwningPid, modName);
    }

    if (pUdpTable) { free(pUdpTable); pUdpTable = NULL; }
    if (modInfo)   { free(modInfo);   modInfo   = NULL; }

    return;
}

int main()
{
    // This library is not guaranteed to be loaded and is required to list Service names when displaying module info
    LoadLibraryA("advapi32.dll");
    get_tcp_info();
    get_udp_info();
    return 0;
}
