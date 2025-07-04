//PAGE_NOACCESS Debug/Hook proof of concept by AlSch092 @ Github
// To be paired with manual mapping injection, undetectable to many usermode anti-cheats and some kernelmode (inject before any AC driver is loaded to make sure you can grab a handle)
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <iostream>

const char* TargetModuleName = "MapleStoryN.exe"; //change this to whatever you want

static std::unordered_set<void*> breakpoints;
static std::unordered_map<void*, std::string> labels;
static std::unordered_map<void*, BYTE*> pageMap;
static bool stepping = false;
static PVOID vehHandle = nullptr;

CRITICAL_SECTION cs;
std::atomic_flag vehLock = ATOMIC_FLAG_INIT;
std::atomic<bool> gNeedsRearm = false;

void LoadBreakpointsFromFile(const char* path);
void PlaceBreakpoints();

static void LogData(CONTEXT* ctx, void* rip) 
{
    //printf("\n[VEH] Breakpoint at %p\n", rip);
    //printf("RAX: %llx | RBX: %llx | RCX: %llx | RDX: %llx\n", ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx);
    //printf("RSI: %llx | RDI: %llx\n", ctx->Rsi, ctx->Rdi);
    //printf("R8: %llx | R9: %llx | R10: %llx | R11: %llx | R12: %llx | R13: %llx | R14: %llx | R15: %llx\n", ctx->R8, ctx->R9, ctx->R10, ctx->R11, ctx->R12, ctx->R13, ctx->R14, ctx->R15);
    //printf("RSP: %llx | RBP: %llx | RIP: %llx\n", ctx->Rsp, ctx->Rbp, ctx->Rip);
    //printf("--------------------------------------\n");

    uint64_t packet_buff = ctx->Rdx; //packet buffer addr (MapleStoryN), at our breakpointed/hooked address, RDX contains the send packet buffer and R8 is the size
    uint32_t packet_size = ctx->R8; //packet size, change this to however you want for your specific case
    
    if (!packet_buff || packet_size > 200)
    {
		printf("[WARNING] Null packet buffer addr or size is too large: %d\n", packet_size);
        return;
    }

	printf("Packet Size: %d, Packet Buffer: \n", packet_size); //you can also write registers & memory here, making this great for packet modification in games where you can't otherwise hook memory due to AC

    printf("==========================================================\n");
    for (int i = 0; i < packet_size; i++)
    {
		printf("%02X ", *(BYTE*)(packet_buff + i));
    }

    printf("\n==========================================================\n");
}

#pragma code_seg(push, ".veh")  //put VEH handler in its own section (for testing, my program only had 1 page in .text and we were setting PAGE_NOACCESS on this, causing a deadlock/exception loop)
DWORD WINAPI RearmerThread(LPVOID) 
{
    while (true) 
    {
        if (gNeedsRearm.exchange(false)) 
        {
            Sleep(200); // small delay before re-arming
            PlaceBreakpoints(); // safe to run outside VEH
        }
        Sleep(200);
    }
    return 0;
}

LONG CALLBACK VEHHandler(PEXCEPTION_POINTERS ep) 
{
	EnterCriticalSection(&cs); //we only want 1 thread at most going through this, so add a lock (might degrade performance a bit, but was fine during my tests on different games)

    CONTEXT* ctx = ep->ContextRecord;

    void* faultAddr = (void*)ep->ExceptionRecord->ExceptionInformation[1];

    if (breakpoints.count(faultAddr) && ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->ExceptionInformation[0] == 8) 
    {
        void* rip = (void*)ctx->Rip;
        LogData(ctx, rip);
        DWORD oldProt;
        VirtualProtect(pageMap[faultAddr], 1, PAGE_EXECUTE_READ, &oldProt); //set page back to normal
        gNeedsRearm.store(true);
		LeaveCriticalSection(&cs);
        return EXCEPTION_CONTINUE_EXECUTION; //execution should be fine after setting page protections
    }
    //since it's possible for an address other than our desired breakpoint to be executed (in a PAGE_NOACCESS state), we need to catch it, and single-step until we hit our desired breakpoint addr
    else if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->ExceptionInformation[0] == 8)
    {
        if (breakpoints.count(faultAddr)) 
        {
            DWORD oldProt;
            VirtualProtect(pageMap[faultAddr], 1, PAGE_EXECUTE_READ, &oldProt);
            ctx->EFlags |= 0x100; // set trap Flag
            stepping = true;
            LeaveCriticalSection(&cs);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    else if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP && stepping) 
    {   
        void* rip = (void*)ctx->Rip;

        if (breakpoints.count(rip)) 
        {
            LogData(ctx, rip);
            stepping = false;
			ctx->EFlags &= ~0x100; // clear trap Flag
        }
        else 
        {
            for (auto& [addr, page] : pageMap) 
            {
                DWORD oldProt;
                VirtualProtect(page, 1, PAGE_NOACCESS, &oldProt);
            }
        }

        LeaveCriticalSection(&cs);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LeaveCriticalSection(&cs);
    return EXCEPTION_CONTINUE_SEARCH;
}
#pragma code_seg(pop)

void PlaceBreakpoints()
{
	for (auto& [addr, page] : pageMap) 
    {
		DWORD oldProt;
		VirtualProtect(page, 1, PAGE_NOACCESS, &oldProt);
	}
}

void LoadBreakpointsFromFile(const char* path) 
{
    std::ifstream infile(path);
    std::string line;
    uint64_t base = (uint64_t)GetModuleHandleA(TargetModuleName);

	while (std::getline(infile, line))  //each line of your file should look like this: "123ABC,myBreakpoint" (without quotes)
    {
        size_t delim = line.find(',');
        if (delim == std::string::npos) continue;

        std::string offsetStr = line.substr(0, delim);
        std::string label = line.substr(delim + 1);

        uint64_t offset = std::stoull(offsetStr, nullptr, 16); //convert str to base16
        void* addr = (void*)(base + offset);
        BYTE* page = (BYTE*)((uintptr_t)addr & ~0xFFF);

        if (breakpoints.count(addr) == 0)
        {
            breakpoints.insert(addr);
            labels[addr] = label;
            pageMap[addr] = page;
        }

        DWORD oldProt;
        VirtualProtect(page, 0x1000, PAGE_NOACCESS, &oldProt);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved) 
{
    if (ul_reason == DLL_PROCESS_ATTACH) 
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONIN$", "r", stdin);

        InitializeCriticalSection(&cs);
        vehHandle = AddVectoredExceptionHandler(1, VEHHandler);
        CreateThread(0, 0, RearmerThread, 0, 0, 0);
		LoadBreakpointsFromFile(".\\breakpoints.txt"); //if you're injecting into a process, make sure this file is in the same directory as the process

    }
    else if (ul_reason == DLL_PROCESS_DETACH) 
    {
        if (vehHandle) 
            RemoveVectoredExceptionHandler(vehHandle);
    }

    return TRUE;
}
