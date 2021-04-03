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

struct SModuleInfo
{
  size_t baseAddress;
  size_t endAddress;
};

struct SThreadRip
{
  DWORD threadId;
  HANDLE handle;
  size_t lastRip;
};

struct SProfileResult
{
  std::deque<size_t> directHits;
};

struct SEvalResult
{
  std::vector<SPerfEval> eval;
};

struct SAppInfo
{
  std::vector<SThreadRip> threads;
  SModuleInfo modules;
};

SProfileResult ProfileApplication(SAppInfo &appInfo);
void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt);
SEvalResult EvaluateSession(_In_ CComPtr<IDiaDataSource> &pdbSource, _Inout_ SProfileResult &perfSession);

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

  SAppInfo appInfo;
  
  // Start Debugging. (Apparently required for `EnumProcessModules` to work)
  {
    DEBUG_EVENT debugEvent;

    FATAL_IF(!WaitForDebugEvent(&debugEvent, 1000), "Failed to debug process. Aborting.");

    do
    {
      UpdateAppInfo(appInfo, debugEvent);
      FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE), "Failed to continue debugged process. Aborting.");
    } while (WaitForDebugEvent(&debugEvent, 1));
  }

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

    appInfo.modules.baseAddress = (size_t)pBaseAddress;
    appInfo.modules.endAddress = appInfo.modules.baseAddress + (size_t)ntHeader.OptionalHeader.SizeOfCode;
  }

  puts("Starting Profiling Loop...");

  SProfileResult profileSession = ProfileApplication(appInfo);

  printf("Profiler Stopped.\nCaptured %" PRIu64 " direct hits.\n", profileSession.directHits.size());
  
  puts("Evaluating Profiling Data...");

  SEvalResult evaluation = EvaluateSession(pdbSource, profileSession);

  puts("Sorting Evaluation...");

  std::sort(evaluation.eval.begin(), evaluation.eval.end());

  puts("\n\nResults:\n");

  size_t count = 0;

  for (const auto &_func : evaluation.eval)
  {
    ++count;

    if (count > 50)
      break;

    printf("#%02" PRIu64 " | % 6" PRIu64 " %ws\n", count, _func.hitsOffset.size(), _func.symbolName);
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

SProfileResult ProfileApplication(SAppInfo &appInfo)
{
  SProfileResult ret;

  DEBUG_EVENT debugEvent;

  CONTEXT threadContext;
  threadContext.ContextFlags = CONTEXT_CONTROL;

  while (true)
  {
    const bool hasDebugEvent = WaitForDebugEvent(&debugEvent, 0);

    if (hasDebugEvent)
    {
      switch (debugEvent.dwDebugEventCode)
      {
      case EXIT_PROCESS_DEBUG_EVENT:
      {
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        return ret;
      }

      default:
      {
        UpdateAppInfo(appInfo, debugEvent);
        break;
      }
      }
    }

    for (auto &_thread : appInfo.threads)
      if (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId)
        SuspendThread(_thread.handle);

    for (auto &_thread : appInfo.threads)
    {
      if (GetThreadContext(_thread.handle, &threadContext))
      {
        if (threadContext.Rip != _thread.lastRip)
        {
          const size_t relativeAddress = threadContext.Rip - appInfo.modules.baseAddress;

          if (relativeAddress < appInfo.modules.endAddress)
            ret.directHits.emplace_back(relativeAddress);

          _thread.lastRip = threadContext.Rip;
        }
      }
    }

    for (auto &_thread : appInfo.threads)
      if (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId)
        ResumeThread(_thread.handle);

    if (hasDebugEvent)
    {
      if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE))
      {
        puts("Failed to Continue Application. Stopping the Profiler.");
        break;
      }
    }
    else
    {
      YieldProcessor();
    }
  }

  return ret;
}

////////////////////////////////////////////////////////////////////////////////

void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt)
{
  switch (evnt.dwDebugEventCode)
  {
  case CREATE_THREAD_DEBUG_EVENT:
  {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, evnt.dwThreadId);

    if (thread == INVALID_HANDLE_VALUE || thread == nullptr)
      printf("Failed to open Thread %" PRIu32 " with error %" PRIu32 ".\n", evnt.dwThreadId, GetLastError());
    else
      appInfo.threads.push_back({ evnt.dwThreadId, thread, 0 });

    break;
  }

  case EXIT_THREAD_DEBUG_EVENT:
  {
    for (size_t i = 0; i < appInfo.threads.size(); i++)
    {
      if (evnt.dwThreadId == appInfo.threads[i].threadId)
      {
        CloseHandle(appInfo.threads[i].handle);
        appInfo.threads.erase(appInfo.threads.begin() + i);
        break;
      }
    }

    break;
  }

  case EXIT_PROCESS_DEBUG_EVENT:
    FATAL("Unexpected `EXIT_PROCESS_DEBUG_EVENT`. Aborting.");
    break;

  case LOAD_DLL_DEBUG_EVENT:
    break;

  case UNLOAD_DLL_DEBUG_EVENT:
    break;
  }
}

////////////////////////////////////////////////////////////////////////////////

DWORD EvaluateSymbol(_In_ const CComPtr<IDiaSymbol> &symbol, _Inout_ std::vector<SPerfEval> &evaluation, _Inout_ std::deque<size_t> &positions)
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

    while (positions.size() > 0 && positions[0] < lastVirtualAddress)
      positions.pop_front();

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

SEvalResult EvaluateSession(_In_ CComPtr<IDiaDataSource> &pdbSource, _Inout_ SProfileResult &perfSession)
{
  SEvalResult ret;

  std::sort(perfSession.directHits.begin(), perfSession.directHits.end());

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
      lastVirtualAddress = EvaluateSymbol(symbol, ret.eval, perfSession.directHits);

      symbol = nullptr;
      fetchedSymbolCount = 0;

      if (FAILED(hr = pEnumByAddr->Next(1, &symbol, &fetchedSymbolCount)))
        break;

    } while (fetchedSymbolCount == 1);

    symbol = nullptr;

    FATAL_IF(FAILED(pEnumByAddr->symbolByRVA(lastVirtualAddress, &symbol)), "Failed to retrieve Symbol by RVA.");

    do
    {
      lastVirtualAddress = EvaluateSymbol(symbol, ret.eval, perfSession.directHits);

      symbol = nullptr;
      fetchedSymbolCount = 0;

      if (FAILED(hr = pEnumByAddr->Prev(1, &symbol, &fetchedSymbolCount)))
        break;

    } while (fetchedSymbolCount == 1);

    FATAL_IF(FAILED(hr), "Failed to retrieve next element.");
  }

  return ret;
}
