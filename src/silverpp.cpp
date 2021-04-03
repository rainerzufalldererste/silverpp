#include <windows.h>
#include <debugapi.h>
#include <psapi.h>
#include <atlutil.h>
#include <dia2.h>
#include <diacreate.h>
#include <cvconst.h>

#include <vector>
#include <deque>
#include <algorithm>

#include <inttypes.h>

////////////////////////////////////////////////////////////////////////////////

#define FATAL(x, ...) do { printf(x "\n", __VA_ARGS__); __debugbreak(); ExitProcess((UINT)-1); } while (0)
#define FATAL_IF(conditional, x, ...) do { if (conditional) { FATAL(x, __VA_ARGS__); } } while (0)

////////////////////////////////////////////////////////////////////////////////

struct SPerfEval
{
  wchar_t symbolName[256] = {};
  size_t symbolStartPos;
  std::vector<uint32_t> hitsOffset;

  inline bool operator < (const SPerfEval &other)
  {
    return hitsOffset.size() > other.hitsOffset.size();
  }
};

void EvaluateSession(_Out_ std::vector<SPerfEval> &evaluation, _In_ CComPtr<IDiaDataSource> &pdbSource, _Inout_ std::deque<size_t> &positions);

////////////////////////////////////////////////////////////////////////////////

int32_t main(void)
{
  int32_t argc = 0;
  wchar_t **pArgv = CommandLineToArgvW(GetCommandLineW(), &argc);
  FATAL_IF(argc == 1, "Usage: silverpp <ExecutablePath> <Args>");

  wchar_t workingDirectory[MAX_PATH];
  FATAL_IF(0 == GetCurrentDirectory(ARRAYSIZE(workingDirectory), workingDirectory), "Failed to retrieve working directory. Aborting.");

  wchar_t *appPath = pArgv[1];
  wchar_t *pdbPath = pArgv[1];

  CComPtr<IDiaDataSource> pdbSource;

  // Attempt to read PDB.
  {
    FATAL_IF(FAILED(CoInitialize(nullptr)), "Failed to Initialize. Aborting.");

    FATAL_IF(FAILED(CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&pdbSource)), "Failed to retrieve an instance of the PDB Parser.");

    if (FAILED(pdbSource->loadDataFromPdb(pdbPath))) // Currently not supported.
      if (FAILED(pdbSource->loadDataForExe(appPath, nullptr, nullptr)))
        FATAL("Failed to find pdb for the specified path.");
  }

  PROCESS_INFORMATION processInfo;
  ZeroMemory(&processInfo, sizeof(processInfo));

  // Start Process.
  {
    STARTUPINFO startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    printf("Attempting to launch '%ws'...\n", appPath);

    FATAL_IF(!CreateProcessW(appPath, L"", NULL, NULL, FALSE, DEBUG_PROCESS | CREATE_NEW_CONSOLE, NULL, workingDirectory, &startupInfo, &processInfo), "Unable to start process. Aborting.");
  }

  DEBUG_EVENT debugEvent;

  FATAL_IF(!WaitForDebugEvent(&debugEvent, 1000), "Failed to debug process. Aborting.");

  do
  {
    FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE), "Failed to continue debugged process. Aborting.");
  } while (WaitForDebugEvent(&debugEvent, 1));

  size_t moduleVirtualBaseAddress = 0;

  // Get Base Address of Main Module.
  {
    DWORD bytesRequired = 0;
    HMODULE modules[1024];
    FATAL_IF(!EnumProcessModules(processInfo.hProcess, modules, sizeof(modules), &bytesRequired), "Failed to retrieve Process Modules. Aborting.");

    const uint8_t *pBaseAddress = reinterpret_cast<const uint8_t *>(modules[0]);
    IMAGE_DOS_HEADER moduleHeader;
    size_t bytesRead = 0;
    FATAL_IF(!ReadProcessMemory(processInfo.hProcess, pBaseAddress, &moduleHeader, sizeof(moduleHeader), &bytesRead) || bytesRead != sizeof(moduleHeader), "Failed to Read Module DOS Header. Aborting.");

    IMAGE_NT_HEADERS ntHeader;
    FATAL_IF(!ReadProcessMemory(processInfo.hProcess, pBaseAddress + moduleHeader.e_lfanew, &ntHeader, sizeof(ntHeader), &bytesRead) || bytesRead != sizeof(ntHeader), "Failed to Read Module NT Header. Aborting.");

    moduleVirtualBaseAddress = (size_t)pBaseAddress + ntHeader.OptionalHeader.BaseOfCode;
  }

  size_t lastRip = 0;
  std::deque<size_t> positions;

  puts("Starting Profiling Loop...");

  CONTEXT threadContext;
  threadContext.ContextFlags = CONTEXT_CONTROL;

  // Profile Stuff.
  while (true)
  {
    const bool hasDebugEvent = WaitForDebugEvent(&debugEvent, 0);

    if (hasDebugEvent)
    {
      if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        break;

      if (debugEvent.dwThreadId != processInfo.dwThreadId)
      {
        if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE))
        {
          puts("Failed to Continue Application. Stopping the Profiler.");
          break;
        }

        SuspendThread(processInfo.hThread);
      }
    }

    if (GetThreadContext(processInfo.hThread, &threadContext))
    {
      if (threadContext.Rip != lastRip)
      {
        positions.emplace_back(threadContext.Rip - moduleVirtualBaseAddress);
        lastRip = threadContext.Rip;
      }
    }

    if (hasDebugEvent)
    {
      if (debugEvent.dwThreadId == processInfo.dwThreadId)
      {
        if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE))
        {
          puts("Failed to Continue Application. Stopping the Profiler.");
          break;
        }
      }
      else
      {
        ResumeThread(processInfo.hThread);
      }
    }
    else
    {
      YieldProcessor();
    }
  }

  printf("Profiler Stopped.\nCaptured %" PRIu64 " positions on thread %" PRIu32 ".\n", positions.size(), processInfo.dwThreadId);

  puts("Sorting Profiling Data...");

  std::sort(positions.begin(), positions.end());

  puts("Evaluating Profiling Data...");

  std::vector<SPerfEval> evaluation;

  EvaluateSession(evaluation, pdbSource, positions);

  puts("Sorting Evaluation...");

  std::sort(evaluation.begin(), evaluation.end());

  puts("\n\nResults:\n");

  size_t count = 0;

  for (const auto &_func : evaluation)
  {
    ++count;

    if (count > 50)
      break;

    printf("#%02" PRIu64 " | % 6" PRIu64 " %ws\n", count, _func.hitsOffset.size(), _func.symbolName);
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

DWORD EvaluateSymbol(CComPtr<IDiaSymbol> &symbol, _Out_ std::vector<SPerfEval> &evaluation, _Inout_ std::deque<size_t> &positions)
{
  static DWORD lastTag = SymTagNull;
  static DWORD lastVirtualAddress = 0;
  static wchar_t symbolName[sizeof(SPerfEval::symbolName) / sizeof(wchar_t)] = L"";

  DWORD virtualAddress;
  DWORD tag;

  if (symbol->get_relativeVirtualAddress(&virtualAddress) != S_OK)
    virtualAddress = 0;

  if (SUCCEEDED(symbol->get_symTag(&tag)) && symbolName[0] != L'\0' && lastTag == SymTagFunction && virtualAddress > lastVirtualAddress)
  {
    SPerfEval func;
    func.symbolStartPos = lastVirtualAddress;
  
    memcpy(func.symbolName, symbolName, sizeof(symbolName));
    symbolName[0] = L'\0';
  
    while (positions.size() > 0 && positions[0] >= lastVirtualAddress && positions[0] < virtualAddress)
    {
      func.hitsOffset.emplace_back((uint32_t)(positions.front() - lastVirtualAddress));
      positions.pop_front();
    }
  
    if (func.hitsOffset.size() > 0)
      evaluation.emplace_back(std::move(func));
  }
  
  if (tag == SymTagFunction)
  {
    wchar_t *currentSymbolName = nullptr;
  
    if (FAILED(symbol->get_name(&currentSymbolName)))
    {
      if (currentSymbolName != nullptr)
        SysFreeString(currentSymbolName);
  
      symbolName[0] = L'\0';
      tag = SymTagNull;
    }
    else
    {
      const size_t length = min(sizeof(symbolName) - sizeof(wchar_t), wcslen(currentSymbolName) * sizeof(wchar_t));
      memcpy(symbolName, currentSymbolName, length);
      symbolName[length / sizeof(wchar_t)] = L'\0';
      SysFreeString(currentSymbolName);
    }
  }

  lastTag = tag;
  return lastVirtualAddress = virtualAddress;
}

void EvaluateSession(_Out_ std::vector<SPerfEval> &evaluation, _In_ CComPtr<IDiaDataSource> &pdbSource, _Inout_ std::deque<size_t> &positions)
{
  CComPtr<IDiaSession> session;
  FATAL_IF(FAILED(pdbSource->openSession(&session)), "Failed to Open Session.");

  CComPtr<IDiaSymbol> global;
  FATAL_IF(FAILED(session->get_globalScope(&global)), "Failed to retrieve Global Scope.");

  DWORD id = 0;
  FATAL_IF(FAILED(global->get_symIndexId(&id)) || id == 0, "Failed to retrieve Global Symbol Index ID.");

  CComPtr<IDiaEnumSymbolsByAddr> pEnumByAddr;
  FATAL_IF(FAILED(session->getSymbolsByAddr(&pEnumByAddr)), "Failed to get Enumerator for Symbols by Address.");

  CComPtr<IDiaSymbol> symbol;
  FATAL_IF(FAILED(pEnumByAddr->symbolByAddr(1, 0, &symbol)), "Failed to get first Symbol from Enumerator");

  DWORD lastVirtualAddress = 0;

  if (SUCCEEDED(symbol->get_relativeVirtualAddress(&lastVirtualAddress)))
  {
    symbol = nullptr;

    FATAL_IF(FAILED(pEnumByAddr->symbolByRVA(lastVirtualAddress, &symbol)), "Failed to get Symbol from Enumerator.");

    HRESULT hr;
    ULONG fetchedSymbolCount = 0;

    do
    {
      lastVirtualAddress = EvaluateSymbol(symbol, evaluation, positions);

      symbol = nullptr;
      fetchedSymbolCount = 0;

      if (FAILED(hr = pEnumByAddr->Next(1, &symbol, &fetchedSymbolCount)))
        break;

    } while (fetchedSymbolCount == 1);

    symbol = nullptr;

    FATAL_IF(FAILED(pEnumByAddr->symbolByRVA(lastVirtualAddress, &symbol)), "Failed to retrieve Symbol by RVA.");

    do
    {
      lastVirtualAddress = EvaluateSymbol(symbol, evaluation, positions);

      symbol = nullptr;
      fetchedSymbolCount = 0;

      if (FAILED(hr = pEnumByAddr->Prev(1, &symbol, &fetchedSymbolCount)))
        break;

    } while (fetchedSymbolCount == 1);

    FATAL_IF(FAILED(hr), "Failed to retrieve next element.");
  }
}
