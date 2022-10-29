////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2021, Christoph Stiller. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without 
// modification, are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation 
//    and/or other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <debugapi.h>
#include <psapi.h>
#include <atlutil.h>
#include <dia2.h>
#include <diacreate.h>
#include <cvconst.h>
#include <initguid.h>

#include <vector>
#include <deque>
#include <algorithm>
#include <memory>

#include <inttypes.h>

#ifndef NO_DISASM
extern "C"
{
#define ZYCORE_STATIC_DEFINE
#include <Zydis/Zydis.h>
}
#endif

////////////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG
#define DBG_BREAK() __debugbreak()
#else
#define DBG_BREAK()
#endif

#define FATAL(x, ...) do { printf(x "\n", __VA_ARGS__); DBG_BREAK(); ExitProcess((UINT)-1); } while (0)
#define FATAL_IF(conditional, x, ...) do { if (conditional) { FATAL(x, __VA_ARGS__); } } while (0)
#define ERROR_RETURN_IF(conditional, x, ...) do { if (conditional) { printf(x "\n", __VA_ARGS__); DBG_BREAK(); return false; } } while (0)
#define ERROR_CONTINUE_IF(conditional, x, ...) do { if (conditional) { printf(x "\n", __VA_ARGS__); DBG_BREAK(); continue; } } while (0)

////////////////////////////////////////////////////////////////////////////////

struct SForeignHitEval
{
  uint32_t offset;
  uint8_t foreignModuleIndex;
  uint16_t functionIndex;
  size_t count;

  inline bool operator < (const SForeignHitEval &other)
  {
    if (offset == other.offset)
      return count > other.count;

    return offset < other.offset;
  }
};

struct SPerfEval
{
  wchar_t symbolName[384] = {};
  size_t symbolStartPos, symbolEndPos;
  DWORD sector, offset;
  uint8_t moduleIndex;

  std::vector<uint32_t> hitsOffset;
  std::vector<SForeignHitEval> foreignHits;

  inline bool operator < (const SPerfEval &other)
  {
    return hitsOffset.size() > other.hitsOffset.size();
  }
};

static uint8_t _NextModuleIndex = 1;

struct SModuleInfo
{
  size_t moduleBaseAddress;
  size_t moduleEndAddress;
  size_t startAddress;
  size_t endAddress;
  wchar_t filename[MAX_PATH] = {};
  size_t nameOffset = 0;
  uint8_t *pBinary = nullptr;
  size_t binaryLength = 0;
  uint8_t moduleIndex;

  bool hasDisasm = false;

  CComPtr<IDiaSession> pdbSession;

#ifndef _NO_DISASM
  ZydisDecoder decoder;
  ZydisFormatter formatter;
#endif

  ~SModuleInfo()
  {
    if (pBinary != nullptr)
      free(pBinary);
  }

  inline bool operator < (const SModuleInfo &other)
  {
    return moduleIndex < other.moduleIndex;
  }
};

struct SLibraryFunction
{
  char name[1024];
  size_t virtualAddressOffset;

  inline bool operator < (const SLibraryFunction &other)
  {
    return virtualAddressOffset < other.virtualAddressOffset;
  }
};

struct SNamedLibraryInfo
{
  wchar_t filename[MAX_PATH];
  size_t nameOffset = 0;
  size_t moduleBaseAddress;
  size_t moduleEndAddress;
  size_t startAddress;
  size_t endAddress;
  bool loaded;

  std::vector<SLibraryFunction> functions;
};

struct SThreadRip
{
  DWORD threadId;
  HANDLE handle;
  size_t lastRip;
};

struct SProfileOptions
{
  bool getStackTraceOnExtern = false;
  bool fastStackTrace = false;
  bool alwaysGetStackTrace = false;
  bool favorPerformance = true;
  bool analyzeDelays = false;
  size_t samplingDelay = 0;
};

struct SProfileHit
{
  size_t packed;

  inline const SProfileHit() { }

  inline const SProfileHit(const size_t address, const uint8_t moduleIndex)
  {
    packed = address | ((size_t)moduleIndex << 56);
  }

  inline size_t GetAddress() const
  {
    return packed & (size_t)0x00FFFFFFFFFFFFFF;
  }

  inline size_t GetModule() const
  {
    return (packed >> 56) & 0xFF;
  }

  inline operator size_t () const
  {
    return GetAddress();
  }

  inline bool operator < (const SProfileHit &other) const
  {
    return packed < other.packed;
  }
};

struct SProfileIndirectHit
{
  SProfileHit ownedModuleHit;
  size_t packed;

  inline const SProfileIndirectHit() { }

  inline const SProfileIndirectHit(const size_t address, const uint8_t foreignModuleIndex, const size_t ownedModuleHitAddress, const uint8_t ownedModuleIndex) :
    ownedModuleHit(ownedModuleHitAddress, ownedModuleIndex)
  {
    packed = address | ((size_t)foreignModuleIndex << 56);
  }

  inline size_t GetAddress() const
  {
    return packed & (size_t)0x00FFFFFFFFFFFFFF;
  }

  inline size_t GetForeignModule() const
  {
    return (packed >> 56) & 0xFF;
  }

  // 0xFFFF means the function was not found.
  inline size_t GetFunctionIndex() const
  {
    return (packed >> 39) & 0xFFFF;
  }

  inline size_t GetFunctionOffset() const
  {
    return packed & 0xFFFFFFFF;
  }

  inline bool IsFound() const
  {
    return (bool)((packed >> 55) & 0b1);
  }

  inline operator size_t () const
  {
    return GetAddress();
  }

  inline void SetIndirectPart(const size_t address, const uint8_t foreignModuleIndex)
  {
    packed = address | ((size_t)foreignModuleIndex << 56);
  }

  inline void ToFunctionOffset(const size_t offset, const size_t functionIndex)
  {
    packed = (packed & 0xFF0000000000000) | (1ULL << 55) | (offset & 0xFFFFFFFF) | ((functionIndex & 0xFFFF) << 39);
  }
};

inline bool SortByForeignModule(const SProfileIndirectHit &a, const SProfileIndirectHit &b)
{
  return a.packed < b.packed;
}

inline bool SortByOwnedModule(const SProfileIndirectHit &a, const SProfileIndirectHit &b)
{
  return a.ownedModuleHit.packed < b.ownedModuleHit.packed;
}

struct SProcessProfileResult
{
  uint32_t processId;

  std::vector<SProfileHit> directHits;
  std::vector<size_t> directHitIndexAtSecond;

  std::vector<SProfileIndirectHit> indirectHits;
  std::vector<size_t> indirectHitIndexAtSecond;
};

struct SProfileResult
{
  SProcessProfileResult procs[1];
  size_t procs_size = 0;
};

struct SEvalResult
{
  std::vector<SPerfEval> eval;
};

struct SProcessInfo
{
  DWORD processId;
  bool hasName = false;
  char name[MAX_PATH];
  std::vector<SThreadRip> threads;
  std::vector<SModuleInfo> modules;
  std::vector<SModuleInfo> inactiveModules;
  std::vector<SNamedLibraryInfo> foreignModules;
  HANDLE processHandle;
  size_t minimalVirtualAddress;
  size_t maximalVirtualAddress;
  size_t minimalIndirectVirtualAddress = (size_t)-1;
  size_t maximalIndirectVirtualAddress = 0;
};

struct SAppInfo
{
  SProcessInfo procs[1];
  size_t procs_size = 0;
  size_t runningProcesses = 0;
};

struct SLineEval
{
  uint32_t fileIndex;
  uint32_t line;
  size_t startAddress, endAddress;
  size_t hits;

  inline SLineEval(const uint32_t fileIndex, const uint32_t line, const size_t startAddress, const size_t endAddress, const size_t hits) :
    fileIndex(fileIndex),
    line(line),
    startAddress(startAddress),
    endAddress(endAddress),
    hits(hits)
  { }

  inline bool operator < (const SLineEval &other) const
  {
    if (fileIndex < other.fileIndex)
      return true;
    else if (fileIndex > other.fileIndex)
      return false;

    if (line < other.line)
      return true;

    return false;
  }
};

struct SSourceFile
{
  wchar_t filename[MAX_PATH];
  DWORD sourceFileId;
};

struct SFuncEval
{
  std::vector<SLineEval> lines;
  std::vector<SSourceFile> files;
};

enum ConsoleColor
{
  CC_Black,
  CC_DarkBlue,
  CC_DarkGreen,
  CC_DarkCyan,
  CC_DarkRed,
  CC_DarkMagenta,
  CC_DarkYellow,
  CC_BrightGray,
  CC_DarkGray,
  CC_BrightBlue,
  CC_BrightGreen,
  CC_BrightCyan,
  CC_BrightRed,
  CC_BrightMagenta,
  CC_BrightYellow,
  CC_White,
};

struct SFuncLineOptions
{
  bool disasmExpensiveLines = true;
  float expensiveLineThreshold = 0.5;
  float relevantLineThreshold = 0.1;
  float disasmLineThreshold = 0.3;
  float expensiveAsmThreshold = 0.1;
  size_t minAsmSamples = 8;
};

inline bool CompareHits(const SLineEval &a, const SLineEval &b)
{
  return a.hits > b.hits;
}

static HANDLE _StdOutHandle = nullptr;

inline void SetConsoleColor(const ConsoleColor foreground, const ConsoleColor background)
{
  if (_StdOutHandle == nullptr)
    _StdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

  const WORD fgColour = (foreground & 0xF);
  const WORD bgColour = (background & 0xF);

  if (_StdOutHandle != nullptr && _StdOutHandle != INVALID_HANDLE_VALUE)
    SetConsoleTextAttribute(_StdOutHandle, fgColour | (bgColour << 4));
}

inline size_t GetConsoleWidth()
{
  if (_StdOutHandle == nullptr)
    _StdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

  CONSOLE_SCREEN_BUFFER_INFO bufferInfo;
  GetConsoleScreenBufferInfo(_StdOutHandle, &bufferInfo);

  return bufferInfo.srWindow.Right - bufferInfo.srWindow.Left + 1;
}

bool GetPdbSource(_Out_ IDiaDataSource **ppPdbSource, const wchar_t *pdbPath, const wchar_t *appPath, SProcessInfo &procInfo);
SProfileResult ProfileApplicationNoStackTrace(SAppInfo &appInfo, const SProfileOptions &options);
void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt);
SEvalResult EvaluateSession(SAppInfo &appInfo, _Inout_ SProcessProfileResult &perfSession, const size_t startIndex, const size_t endIndex, const size_t indirectStartIndex, const size_t indirectEndIndex);
bool GetDetailedEvaluation(_In_ CComPtr<IDiaSession> &session, _In_ const SPerfEval &function, _Inout_ SFuncEval &funcEval);
bool InstrumentFunctionWithSource(SAppInfo &appInfo, const size_t processIndex, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options);
bool LoadBinary(SAppInfo &appInfo, const size_t processIndex, const size_t moduleIndex);
bool InstrumentDisassembly(SAppInfo &appInfo, const size_t processIndex, const SPerfEval &function, const size_t virtualStartAddress, const size_t virtualEndAddress, const SFuncLineOptions &options, const size_t maxLineHits, const size_t *pIndirectHitsStartIndex);

////////////////////////////////////////////////////////////////////////////////

inline void CopyString(wchar_t *dst, const size_t dstBytes, const wchar_t *src)
{
  wcsncpy(dst, src, dstBytes / sizeof(wchar_t));
  //const size_t textLength = min(dstBytes - sizeof(wchar_t), wcslen(src) * sizeof(wchar_t));
  //memcpy(dst, src, textLength);
  //dst[textLength / sizeof(wchar_t)] = '\0';
}

inline void CopyString(char *dst, const size_t dstBytes, const char *src)
{
  strncpy(dst, src, dstBytes);
  //const size_t textLength = min(dstBytes - 1, strlen(src));
  //memcpy(dst, src, textLength);
  //dst[textLength] = '\0';
}

////////////////////////////////////////////////////////////////////////////////

#define CMD_PARAM_ARGS_PASS_THROUGH "--args"
wchar_t _CMD_PARAM_ARGS[] = TEXT(CMD_PARAM_ARGS_PASS_THROUGH);
wchar_t _CMD_PARAM_ARGS_SPACE[] = TEXT(CMD_PARAM_ARGS_PASS_THROUGH) L" ";

#define CMD_PARAM_INDIRECT_HITS "--add-indirect"
wchar_t _CMD_PARAM_INDIRECT_HITS[] = TEXT(CMD_PARAM_INDIRECT_HITS);

#define CMD_PARAM_STACK_TRACE "--stack"
wchar_t _CMD_PARAM_STACK_TRACE[] = TEXT(CMD_PARAM_STACK_TRACE);

#define CMD_PARAM_FAST_STACK_TRACE "--fast-trace"
wchar_t _CMD_PARAM_FAST_STACK_TRACE[] = TEXT(CMD_PARAM_FAST_STACK_TRACE);

#define CMD_PARAM_FAVOR_ACCURACY "--favor-accuracy"
wchar_t _CMD_PARAM_FAVOR_ACCURACY[] = TEXT(CMD_PARAM_FAVOR_ACCURACY);

#define CMD_PARAM_ANALYZE_DELAYS "--analyze-delays"
wchar_t _CMD_PARAM_ANALYZE_DELAYS[] = TEXT(CMD_PARAM_ANALYZE_DELAYS);

#define CMD_PARAM_SAMPLING_DELAY "--delay"
wchar_t _CMD_PARAM_SAMPLING_DELAY[] = TEXT(CMD_PARAM_SAMPLING_DELAY);

#define CMD_PARAM_NO_DISASM "--no-disasm"
wchar_t _CMD_PARAM_NO_DISASM[] = TEXT(CMD_PARAM_NO_DISASM);

#define CMD_PARAM_VERBOSE "--verbose"
wchar_t _CMD_PARAM_VERBOSE[] = TEXT(CMD_PARAM_VERBOSE);

////////////////////////////////////////////////////////////////////////////////

static bool _VerboseLogging = false;

////////////////////////////////////////////////////////////////////////////////

int32_t main(void)
{
  wchar_t *commandLine = GetCommandLineW();

  int32_t argc = 0;
  wchar_t **pArgv = CommandLineToArgvW(commandLine, &argc);
  FATAL_IF(argc == 1, "\nUsage: silverpp <ExecutablePath>\n\n Optional Parameters:\n\n\t" CMD_PARAM_INDIRECT_HITS "\t\t | Trace external Samples back to the calling Function\n\t" CMD_PARAM_STACK_TRACE "\t\t\t | Capture Stack Traces for all Samples\n\t" CMD_PARAM_FAST_STACK_TRACE "\t\t | Fast (but possibly less accurate) Stack Traces\n\t" CMD_PARAM_FAVOR_ACCURACY "\t | Favor Sampling Accuracy over Application Performance\n\t" CMD_PARAM_ANALYZE_DELAYS "\t | Capture sample even if stuck on the same instruction (may cause accidental multiple hits)\n\t" CMD_PARAM_SAMPLING_DELAY " <milliseconds>\t | Additional Sampling Delay (Improves performance at the cost of Samples)\n\t" CMD_PARAM_NO_DISASM "\t\t | Don't display disassembly for expensive lines\n\t" CMD_PARAM_VERBOSE "\t\t | Enable verbose logging\n\t" CMD_PARAM_ARGS_PASS_THROUGH " <Args>\t\t | Pass the remaining Arguments to the Application being profiled\n");

  wchar_t workingDirectory[MAX_PATH];
  FATAL_IF(0 == GetCurrentDirectory(ARRAYSIZE(workingDirectory), workingDirectory), "Failed to retrieve working directory. Aborting.");

  wchar_t *appPath = pArgv[1];
  wchar_t *pdbPath = nullptr;
  wchar_t *args = L"";

  bool analyzeStack = false;
  bool analyzeStackFast = false;
  bool indirectHits = false;
  bool favorAccuracy = false;
  bool analyzeDelays = false;
  bool noDisAsm = false;
  size_t samplingDelay = 0;

  int32_t argsRemaining = argc - 2;
  int32_t argIndex = 2;

  while (argsRemaining > 0)
  {
    if (wcscmp(pArgv[argIndex], _CMD_PARAM_INDIRECT_HITS) == 0)
    {
      indirectHits = true;

      argsRemaining--;
      argIndex++;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_FAVOR_ACCURACY) == 0)
    {
      favorAccuracy = true;

      argsRemaining--;
      argIndex++;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_ANALYZE_DELAYS) == 0)
    {
      analyzeDelays = true;

      argsRemaining--;
      argIndex++;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_STACK_TRACE) == 0)
    {
      analyzeStack = true;

      argsRemaining--;
      argIndex++;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_FAST_STACK_TRACE) == 0)
    {
      analyzeStackFast = true;

      argsRemaining--;
      argIndex++;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_SAMPLING_DELAY) == 0 && argsRemaining > 1)
    {
      samplingDelay = (size_t)max(_wtoi64(pArgv[argIndex + 1]), 0);

      argsRemaining -= 2;
      argIndex += 2;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_NO_DISASM) == 0)
    {
      noDisAsm = true;

      argsRemaining--;
      argIndex++;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_VERBOSE) == 0)
    {
      _VerboseLogging = true;

      argsRemaining--;
      argIndex++;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_ARGS) == 0 && argsRemaining > 1)
    {
      args = commandLine + wcslen(pArgv[0]) + wcslen(pArgv[1]) + 2;

      while (args[sizeof(_CMD_PARAM_ARGS_SPACE)] == '\0' || memcmp(args, _CMD_PARAM_ARGS_SPACE, sizeof(_CMD_PARAM_ARGS_SPACE) - sizeof(wchar_t)) != 0)
        args++;

      args += ARRAYSIZE(_CMD_PARAM_ARGS) - 1;

      break;
    }
    else
    {
      FATAL("Invalid Parameter '%ws'. Aborting.", pArgv[argIndex]);
    }
  }

  FATAL_IF(analyzeStack, "Option '" CMD_PARAM_STACK_TRACE "' is not yet supported.");
  FATAL_IF(analyzeStack && indirectHits, "Option '" CMD_PARAM_INDIRECT_HITS "' cannot be used in conjunction with option '" CMD_PARAM_STACK_TRACE "'.");
  FATAL_IF(analyzeStackFast && !(analyzeStack || indirectHits), "Option '" CMD_PARAM_FAST_STACK_TRACE "' can only be used with '" CMD_PARAM_INDIRECT_HITS "' or '" CMD_PARAM_STACK_TRACE "'.");

  // Does the file even exist?
  {
    const DWORD attributes = GetFileAttributesW(appPath);

    FATAL_IF(attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0, "The target application ('%ws') does not exist. Aborting.", appPath);
  }

  SProcessInfo procInfo;
  procInfo.modules.emplace_back();
  CopyString(procInfo.modules[0].filename, sizeof(procInfo.modules[0].filename), appPath);
  procInfo.modules[0].nameOffset = PathFindFileNameW(procInfo.modules[0].filename) - procInfo.modules[0].filename;
  procInfo.modules[0].moduleIndex = 0;

  // Attempt to read PDB.
  {
    CComPtr<IDiaDataSource> pdbSource;
    HRESULT hr;

    FATAL_IF(FAILED(hr = CoInitialize(nullptr)), "Failed to Initialize. Aborting.");

    FATAL_IF(!GetPdbSource(&pdbSource, pdbPath, appPath, procInfo), "Failed to retrieve pdb source. Aborting.");
  }

  PROCESS_INFORMATION processInfo;
  ZeroMemory(&processInfo, sizeof(processInfo));

  // Start Process.
  {
    STARTUPINFO startupInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    if (wcslen(args) == 0)
      printf("Attempting to launch '%ws'...\n", appPath);
    else
      printf("Attempting to launch '%ws' with arguments '%ws'...\n", appPath, args + 1);

    FATAL_IF(!CreateProcessW(appPath, args, NULL, NULL, FALSE, DEBUG_PROCESS | CREATE_NEW_CONSOLE, NULL, workingDirectory, &startupInfo, &processInfo), "Unable to start process. Aborting.");
  }

  procInfo.processHandle = processInfo.hProcess;
  procInfo.processId = processInfo.dwProcessId;

  SAppInfo appInfo;
  appInfo.procs[appInfo.procs_size++] = std::move(procInfo);

  // Start Debugging.
  {
    DEBUG_EVENT debugEvent;

    FATAL_IF(!WaitForDebugEvent(&debugEvent, 1000), "Failed to debug process. Aborting.");
    UpdateAppInfo(appInfo, debugEvent);

    DWORD continueStatus = DBG_CONTINUE;

    if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
      continueStatus = DBG_EXCEPTION_NOT_HANDLED;

    FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus), "Failed to continue debugged process. Aborting.");
  }

  // Get Base Address of Main Module.
  {
    DWORD bytesRequired = 0;
    HMODULE modules[1024];
    DEBUG_EVENT debugEvent;

    while (0 == EnumProcessModules(appInfo.procs[0].processHandle, modules, sizeof(modules), &bytesRequired) || bytesRequired < 8 * 3) // <module>, ntdll.dll, kernel32.dll
    {
      if (WaitForDebugEvent(&debugEvent, 0))
      {
        UpdateAppInfo(appInfo, debugEvent);

        DWORD continueStatus = DBG_CONTINUE;

        if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
          continueStatus = DBG_EXCEPTION_NOT_HANDLED;

        FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus), "Failed to continue debugged process. Aborting.");
      }
    }

    FATAL_IF(!DebugBreakProcess(appInfo.procs[0].processHandle), "Failed to pause process.");
    FATAL_IF(!WaitForDebugEvent(&debugEvent, 1000), "Failed to pause process. Aborting.");
    UpdateAppInfo(appInfo, debugEvent);

    const uint8_t *pBaseAddress = reinterpret_cast<const uint8_t *>(modules[0]);
    IMAGE_DOS_HEADER moduleHeader;
    size_t bytesRead = 0;
    FATAL_IF(!ReadProcessMemory(appInfo.procs[0].processHandle, pBaseAddress, &moduleHeader, sizeof(moduleHeader), &bytesRead) || bytesRead != sizeof(moduleHeader), "Failed to Read Module DOS Header. Aborting.");

    IMAGE_NT_HEADERS ntHeader;
    FATAL_IF(!ReadProcessMemory(appInfo.procs[0].processHandle, pBaseAddress + moduleHeader.e_lfanew, &ntHeader, sizeof(ntHeader), &bytesRead) || bytesRead != sizeof(ntHeader), "Failed to Read Module NT Header. Aborting.");

    appInfo.procs[0].modules[0].moduleBaseAddress = (size_t)pBaseAddress;
    appInfo.procs[0].modules[0].startAddress = ntHeader.OptionalHeader.BaseOfCode;
    appInfo.procs[0].modules[0].endAddress = appInfo.procs[0].modules[0].startAddress + (size_t)ntHeader.OptionalHeader.SizeOfCode;
    appInfo.procs[0].modules[0].moduleEndAddress = appInfo.procs[0].modules[0].moduleBaseAddress + appInfo.procs[0].modules[0].endAddress;
    appInfo.procs[0].minimalVirtualAddress = appInfo.procs[0].modules[0].moduleBaseAddress;
    appInfo.procs[0].maximalVirtualAddress = appInfo.procs[0].modules[0].moduleEndAddress;

    // Place Main Thread in Threads.
    {
      SThreadRip mainThread;
      mainThread.handle = processInfo.hThread;
      mainThread.threadId = processInfo.dwThreadId;
      mainThread.lastRip = 0;

      appInfo.procs[0].threads.emplace_back(mainThread);
    }

    DWORD continueStatus = DBG_CONTINUE;

    if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
      continueStatus = DBG_EXCEPTION_NOT_HANDLED;

    FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus), "Failed to continue debugged process. Aborting.");
  }

  if (!analyzeStack)
  {
    puts("Starting Profiling Loop...");

    SProfileOptions profileOptions;
    profileOptions.alwaysGetStackTrace = analyzeStack;
    profileOptions.getStackTraceOnExtern = indirectHits;
    profileOptions.fastStackTrace = analyzeStackFast;
    profileOptions.favorPerformance = !favorAccuracy;
    profileOptions.analyzeDelays = analyzeDelays;
    profileOptions.samplingDelay = samplingDelay;

    SProfileResult profileSession = ProfileApplicationNoStackTrace(appInfo, profileOptions);

    printf("Profiler Stopped.\n");

    for (size_t i = 0; i < profileSession.procs_size; i++)
    {
      size_t processIndex = 0;

      for (; processIndex < appInfo.procs_size; processIndex++)
        if (appInfo.procs[processIndex].processId == profileSession.procs[i].processId)
          break;

      printf("#%" PRIu64 " ", i + 1);

      if (processIndex == appInfo.procs_size)
      {
        printf("<Invalid Profile Session for ProcessId %" PRIu32 ">: ", profileSession.procs[i].processId);
      }
      else
      {
        if (appInfo.procs[processIndex].hasName)
          printf("'%s' (ProcessId %" PRIu32 "): ", appInfo.procs[processIndex].name, profileSession.procs[i].processId);
        else
          printf("ProcessId %" PRIu32 ": ", profileSession.procs[i].processId);
      }

      printf("Captured % " PRIu64 " direct (& %" PRIu64 " indirect) hits.\n", profileSession.procs[i].directHits.size(), profileSession.procs[i].indirectHits.size());
    }

    size_t profileSessionIndex = 0;

    if (profileSession.procs_size > 1)
    {
      printf("\n Select Profile Session.\n");

      if (1 != scanf("%" PRIu64 "", &profileSessionIndex))
        profileSessionIndex = 0;

      profileSessionIndex--;

      FATAL_IF(profileSessionIndex > profileSession.procs_size, "Invalid Profile Session Selected. Aborting.");
    }

    size_t totalSamples = 0;

    for (size_t i = 0; i < profileSession.procs_size; i++)
      totalSamples += profileSession.procs[i].directHits.size() + profileSession.procs[i].indirectHits.size();

    FATAL_IF(totalSamples == 0, "No Samples captured.");
    
    size_t startIndex = 0;
    size_t indirectStartIndex = 0;
    size_t endIndex = 0;
    size_t indirectEndIndex = 0;

    {
      constexpr size_t barWidth = 5;
      constexpr size_t barHeight = 8;

      const size_t width = min(GetConsoleWidth() / barWidth, profileSession.procs[profileSessionIndex].directHitIndexAtSecond.size());
      const size_t widthSkips = (profileSession.procs[profileSessionIndex].directHitIndexAtSecond.size() + width - 1) / width;

      size_t maxHeight = 0;
      size_t lastIndex = 0;

      struct Bar
      {
        size_t startIndex;
        size_t endIndex;
        size_t startSecond;
      };

      std::vector<Bar> bars;

      for (size_t i = widthSkips; i < profileSession.procs[profileSessionIndex].directHitIndexAtSecond.size(); i += widthSkips)
      {
        const size_t maxIndex = min(profileSession.procs[profileSessionIndex].directHitIndexAtSecond.size() - 1, i + widthSkips - 1);
        const size_t currentIndex = profileSession.procs[profileSessionIndex].directHitIndexAtSecond[maxIndex - 1];
        const size_t currentCount = currentIndex - lastIndex;

        bars.push_back({ lastIndex, currentIndex, i });

        maxHeight = max(currentCount, maxHeight);
        lastIndex = currentIndex;
      }

      constexpr size_t displayFactor = 4;
      const size_t heightDiv = maxHeight / barHeight;

      const ConsoleColor colors[] = { CC_DarkGreen, CC_BrightGreen, CC_BrightGreen, CC_BrightYellow, CC_BrightYellow, CC_DarkYellow, CC_DarkYellow, CC_BrightRed, CC_DarkRed };
      _STATIC_ASSERT(ARRAYSIZE(colors) == barHeight + 1);

      puts("");

      for (int64_t i = barHeight; i >= 0; i--)
      {
        SetConsoleColor(colors[i], CC_Black);

        for (const auto &_bar : bars)
        {
          const size_t div = ((_bar.endIndex - _bar.startIndex) * displayFactor) / heightDiv;
          size_t rem = 0;

          if (div > (size_t)i * displayFactor)
            rem = div - (size_t)i * displayFactor;

          switch (rem)
          {
          case 0: fputs("     ", stdout); break;
          case 1: fputs("____ ", stdout); break;
          case 2: fputs(".... ", stdout); break;
          case 3: fputs("oooo ", stdout); break;
          default:fputs("#### ", stdout); break;
          }
        }

        puts("");
      }

      SetConsoleColor(CC_BrightGray, CC_Black);

      for (size_t i = 0; i < bars.size(); i++)
        fputs("-----", stdout);

      puts("");

      for (const auto &_bar : bars)
        printf("% 4" PRIu64 "|", _bar.startSecond);

      puts("\n");

      puts("Select Start Second: (0 to include everything)");

      size_t second = 0;

      if (1 != scanf("%" PRIu64 "", &second))
        second = 0;

      if (second == 0)
      {
        startIndex = 0;
        indirectStartIndex = 0;
      }
      else
      {
        startIndex = profileSession.procs[profileSessionIndex].directHitIndexAtSecond[min(second, profileSession.procs[profileSessionIndex].directHitIndexAtSecond.size() - 1)];
        indirectStartIndex = profileSession.procs[profileSessionIndex].indirectHitIndexAtSecond[min(second, profileSession.procs[profileSessionIndex].indirectHitIndexAtSecond.size() - 1)];
      }

      puts("Select End Second: (0 to include everything)");

      if (1 != scanf("%" PRIu64 "", &second))
        second = 0;

      if (second == 0)
      {
        endIndex = profileSession.procs[profileSessionIndex].directHits.size();
        indirectEndIndex = profileSession.procs[profileSessionIndex].indirectHits.size();
      }
      else
      {
        endIndex = profileSession.procs[profileSessionIndex].directHitIndexAtSecond[min(second, profileSession.procs[profileSessionIndex].directHitIndexAtSecond.size() - 1)];
        indirectEndIndex = profileSession.procs[profileSessionIndex].indirectHitIndexAtSecond[min(second, profileSession.procs[profileSessionIndex].indirectHitIndexAtSecond.size() - 1)];
      }
    }

    if (startIndex >= endIndex)
      endIndex = profileSession.procs[profileSessionIndex].directHits.size();

    if (indirectStartIndex >= indirectEndIndex)
      indirectEndIndex = profileSession.procs[profileSessionIndex].indirectHits.size();

    puts("Evaluating Profiling Data...");

    SEvalResult evaluation = EvaluateSession(appInfo, profileSession.procs[profileSessionIndex], startIndex, endIndex, indirectStartIndex, indirectEndIndex);

    puts("Sorting Evaluation...");

    std::sort(evaluation.eval.begin(), evaluation.eval.end());

    puts("\nResults:\n");

    size_t count = 0;

    for (const auto &_func : evaluation.eval)
    {
      ++count;

      if (count > 50)
        break;

      printf("#%02" PRIu64 " | % 6" PRIu64 " | %ws\n", count, _func.hitsOffset.size(), _func.symbolName);
    }

    // Explore Stackless Performance Evaluation.
    {
      size_t processIndex = 0;

      for (; processIndex < appInfo.procs_size; processIndex++)
        if (appInfo.procs[processIndex].processId == profileSession.procs[profileSessionIndex].processId)
          break;

      FATAL_IF(processIndex == appInfo.procs_size, "Invalid ProcessIndex. Aborting.");

      SFuncLineOptions options;
      options.disasmExpensiveLines = !noDisAsm;

      // Select a function to profile and display hits in the source file.
      while (true)
      {
        puts("\n\nIndex (or 0 to exit)?");

        size_t index;

        if (1 != scanf("%" PRIu64 "", &index))
          continue;

        if (index == 0)
          break;

        InstrumentFunctionWithSource(appInfo, processIndex, evaluation, index - 1, options);
      }
    }
  }
  else
  {
    FATAL("StackTrace Analysis is not implemented yet. Aborting.");
  }

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

bool GetPdbSource(_Out_ IDiaDataSource **ppPdbSource, const wchar_t *pdbPath, const wchar_t *appPath, SProcessInfo &procInfo)
{
  HRESULT hr;

  if (FAILED(hr = CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)ppPdbSource)) || *ppPdbSource == nullptr)
  {
    // See https://github.com/baldurk/renderdoc/blob/c3ca732ab9d49d710922ce0243e7bd7b404415d1/renderdoc/os/win32/win32_callstack.cpp

    wchar_t *dllPath = L"msdia140.dll";
    HMODULE msdia140dll = LoadLibraryW(dllPath);
    FATAL_IF(msdia140dll == nullptr, "Failed to load '%ws'. Aborting.", dllPath);

    typedef decltype(&DllGetClassObject) DllGetClassObjectFunc;
    DllGetClassObjectFunc pDllGetClassObject = reinterpret_cast<DllGetClassObjectFunc>(GetProcAddress(msdia140dll, "DllGetClassObject"));
    FATAL_IF(pDllGetClassObject == nullptr, "Failed to load symbol from '%ws'. Aborting.", dllPath);

    CComPtr<IClassFactory> classFactory;
    FATAL_IF(FAILED(hr = pDllGetClassObject(__uuidof(DiaSource), IID_IClassFactory, reinterpret_cast<void **>(&classFactory))) || classFactory == nullptr, "Failed to retrieve COM Class Factory. Aborting.");

    FATAL_IF(FAILED(hr = classFactory->CreateInstance(nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void **>(ppPdbSource))) || *ppPdbSource == nullptr, "Failed to create debug source from class factory. Aborting.");
  }

  if (pdbPath == nullptr || FAILED((*ppPdbSource)->loadDataFromPdb(pdbPath)))
  {
    if (FAILED(hr = (*ppPdbSource)->loadDataForExe(appPath, nullptr, nullptr)))
    {
      printf("Failed to find pdb for '%ws'.\n", appPath);
      return false;
    }
  }

  FATAL_IF(FAILED(hr = (*ppPdbSource)->openSession(&procInfo.modules[0].pdbSession)), "Failed to Open PDB Session.");

  return true;
}

////////////////////////////////////////////////////////////////////////////////

SProfileResult ProfileApplicationNoStackTrace(SAppInfo &appInfo, const SProfileOptions &options)
{
  SProfileResult ret;

  for (size_t i = 0; i < appInfo.procs_size; i++)
  {
    SProcessProfileResult result;
    result.processId = appInfo.procs[i].processId;

    ret.procs[ret.procs_size++] = std::move(result);
  }

  FATAL_IF(options.alwaysGetStackTrace, "`alwaysGetStackTrace` is incompatible with this function. Aborting.");

  DEBUG_EVENT debugEvent;

  CONTEXT threadContext;
  threadContext.ContextFlags = CONTEXT_CONTROL;

  size_t lastTicks = GetTickCount64();

  while (true)
  {
    const bool hasDebugEvent = WaitForDebugEvent(&debugEvent, (DWORD)options.samplingDelay);

    if (hasDebugEvent)
    {
      switch (debugEvent.dwDebugEventCode)
      {
      case EXIT_PROCESS_DEBUG_EVENT:
      {
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);

        appInfo.runningProcesses--;

        char filename[MAX_PATH];
        bool hasName = (0 != GetModuleFileNameExA(debugEvent.u.CreateProcessInfo.hProcess, nullptr, filename, ARRAYSIZE(filename)));

        if (!hasName)
        {
          for (size_t processIndex = 0; processIndex < appInfo.procs_size; processIndex++)
          {
            if (appInfo.procs[processIndex].processId == debugEvent.dwProcessId)
            {
              if (!!(hasName = appInfo.procs[processIndex].hasName))
                CopyString(filename, ARRAYSIZE(filename), appInfo.procs[processIndex].name);

              break;
            }
          }
        }

        if (hasName)
          printf("Process exited. (ProcessId %" PRIu32 ", '%s')\n", debugEvent.dwProcessId, filename);
        else
          printf("Process exited. (ProcessId %" PRIu32 ")\n", debugEvent.dwProcessId);

        if (appInfo.runningProcesses == 0)
          goto after_loop;

        break;
      }

      default:
      {
        UpdateAppInfo(appInfo, debugEvent);
        break;
      }
      }
    }

    const size_t ticks = GetTickCount64();

    constexpr size_t processIndex = 0;

    if (ticks > lastTicks + 1000)
    {
      ret.procs[processIndex].directHitIndexAtSecond.push_back(ret.procs[processIndex].directHits.size());
      ret.procs[processIndex].indirectHitIndexAtSecond.push_back(ret.procs[processIndex].indirectHits.size());
      lastTicks = ticks;
    }

    if (!options.favorPerformance)
      for (auto &_thread : appInfo.procs[processIndex].threads)
        if (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId)
          SuspendThread(_thread.handle);

    for (auto &_thread : appInfo.procs[processIndex].threads)
    {
      if (options.favorPerformance && (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId))
        SuspendThread(_thread.handle);

      if (GetThreadContext(_thread.handle, &threadContext))
      {
        if (options.analyzeDelays || threadContext.Rip != _thread.lastRip)
        {
          bool external = true;

          if (threadContext.Rip >= appInfo.procs[processIndex].minimalVirtualAddress && threadContext.Rip < appInfo.procs[processIndex].maximalVirtualAddress)
          {
            for (const auto &_module : appInfo.procs[processIndex].modules)
            {
              const size_t relativeAddress = threadContext.Rip - _module.moduleBaseAddress;

              if (relativeAddress < _module.endAddress && relativeAddress >= _module.startAddress)
              {
                ret.procs[processIndex].directHits.emplace_back(relativeAddress, (uint8_t)_module.moduleIndex);
                external = false;
                break;
              }
            }
          }

          if (external && options.getStackTraceOnExtern)
          {
            if (options.fastStackTrace)
            {
              constexpr size_t stackDataCount = 64 * sizeof(size_t);
              uint8_t stackData[stackDataCount];

              size_t stackPosition = (threadContext.Rsp & ~(size_t)0x4) - sizeof(stackData) + sizeof(size_t);

              bool found = false;

              while ((stackPosition & 0xFFFFF) > sizeof(stackData) * 2)
              {
                size_t bytesRead = 0;

                if (!ReadProcessMemory(appInfo.procs[processIndex].processHandle, reinterpret_cast<void *>(stackPosition), stackData, sizeof(stackData), &bytesRead))
                  break;

                for (int64_t i = stackDataCount - sizeof(size_t) - 1; i >= 0; i--)
                {
                  const size_t stackValue = *reinterpret_cast<size_t *>(stackData + i);

                  if (stackValue >= appInfo.procs[processIndex].minimalVirtualAddress && stackValue < appInfo.procs[processIndex].maximalVirtualAddress)
                  {
                    for (const auto &_module : appInfo.procs[processIndex].modules)
                    {
                      if (stackValue >= _module.moduleEndAddress)
                        break;

                      const size_t virtualAddress = stackValue - _module.moduleBaseAddress;

                      if (virtualAddress >= _module.startAddress)
                      {
                        ret.procs[processIndex].directHits.emplace_back(virtualAddress, (uint8_t)_module.moduleIndex);
                        found = true;
                        break;
                      }
                    }

                    if (found)
                      break;
                  }
                }

                if (found)
                  break;

                stackPosition -= sizeof(stackData);
              }
            }
            else
            {
              STACKFRAME64 stackFrame;
              ZeroMemory(&stackFrame, sizeof(stackFrame));

              stackFrame.AddrPC.Offset = threadContext.Rip;
              stackFrame.AddrPC.Mode = AddrModeFlat;
              stackFrame.AddrFrame.Offset = threadContext.Rsp;
              stackFrame.AddrFrame.Mode = AddrModeFlat;
              stackFrame.AddrStack.Offset = threadContext.Rsp;
              stackFrame.AddrStack.Mode = AddrModeFlat;

              bool found = false;
              bool hasIndirectHit = false;
              SProfileIndirectHit indirectHit;

              if (threadContext.Rip >= appInfo.procs[processIndex].minimalIndirectVirtualAddress && threadContext.Rip < appInfo.procs[processIndex].maximalIndirectVirtualAddress)
              {
                size_t foreignModuleIndex = (size_t)-1;

                for (const auto &_module : appInfo.procs[processIndex].foreignModules)
                {
                  ++foreignModuleIndex;

                  if (!_module.loaded)
                    continue;

                  const size_t stackRelativeAddress = stackFrame.AddrPC.Offset - _module.moduleBaseAddress;

                  if (stackRelativeAddress < _module.endAddress && stackRelativeAddress >= _module.startAddress)
                  {
                    indirectHit.SetIndirectPart(stackRelativeAddress, (uint8_t)foreignModuleIndex);
                    hasIndirectHit = true;
                    break;
                  }
                }
              }

              while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, appInfo.procs[processIndex].processHandle, _thread.handle, &stackFrame, &threadContext, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
              {
                if (stackFrame.AddrPC.Segment == 0 && stackFrame.AddrPC.Offset >= appInfo.procs[processIndex].minimalVirtualAddress && stackFrame.AddrPC.Offset < appInfo.procs[processIndex].maximalVirtualAddress)
                {
                  for (const auto &_module : appInfo.procs[processIndex].modules)
                  {
                    const size_t stackRelativeAddress = stackFrame.AddrPC.Offset - _module.moduleBaseAddress;

                    if (stackRelativeAddress < _module.endAddress && stackRelativeAddress >= _module.startAddress)
                    {
                      SProfileHit hit(stackRelativeAddress, (uint8_t)_module.moduleIndex);
                      ret.procs[processIndex].directHits.emplace_back(hit);

                      if (hasIndirectHit)
                      {
                        indirectHit.ownedModuleHit = hit;
                        ret.procs[processIndex].indirectHits.emplace_back(indirectHit);
                      }

                      found = true;
                      break;
                    }
                  }

                  if (found)
                    break;
                }

                if (stackFrame.AddrPC.Segment == 0 && stackFrame.AddrPC.Offset >= appInfo.procs[processIndex].minimalIndirectVirtualAddress && stackFrame.AddrPC.Offset < appInfo.procs[processIndex].maximalIndirectVirtualAddress)
                {
                  size_t foreignModuleIndex = (size_t)-1;

                  for (const auto &_module : appInfo.procs[processIndex].foreignModules)
                  {
                    ++foreignModuleIndex;

                    if (!_module.loaded)
                      continue;

                    const size_t stackRelativeAddress = stackFrame.AddrPC.Offset - _module.moduleBaseAddress;

                    if (stackRelativeAddress < _module.endAddress && stackRelativeAddress >= _module.startAddress)
                    {
                      indirectHit.SetIndirectPart(stackRelativeAddress, (uint8_t)foreignModuleIndex);
                      hasIndirectHit = true;
                      break;
                    }
                  }
                }
              }
            }
          }

          _thread.lastRip = threadContext.Rip;
        }
      }

      if (options.favorPerformance && (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId))
        ResumeThread(_thread.handle);
    }

    if (!options.favorPerformance)
      for (auto &_thread : appInfo.procs[processIndex].threads)
        if (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId)
          ResumeThread(_thread.handle);

    if (hasDebugEvent)
    {
      DWORD continueStatus = DBG_CONTINUE;

      if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;

      if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus))
      {
        puts("Failed to continue Application.");
        continue;
      }
    }
    else
    {
      YieldProcessor();
    }
  }

after_loop:

  for (size_t i = 0; i < ret.procs_size; i++)
    ret.procs[i].directHitIndexAtSecond.push_back(ret.procs[i].directHits.size());

  return ret;
}

////////////////////////////////////////////////////////////////////////////////

void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt)
{
  constexpr size_t processIndex = 0;

  switch (evnt.dwDebugEventCode)
  {
  case CREATE_THREAD_DEBUG_EVENT:
  {
    if (evnt.u.CreateThread.hThread == INVALID_HANDLE_VALUE || evnt.u.CreateThread.hThread == nullptr)
    {
      printf("Invalid Thread Handle for ThreadId %" PRIu32 ".\n", evnt.dwThreadId);
    }
    else
    {
      appInfo.procs[processIndex].threads.push_back({ evnt.dwThreadId, evnt.u.CreateThread.hThread, 0 });
    }

    break;
  }

  case CREATE_PROCESS_DEBUG_EVENT:
  {
    appInfo.runningProcesses++;

    if (processIndex == appInfo.procs_size)
    {
      char filename[MAX_PATH];
      bool hasName = (0 != GetModuleFileNameExA(evnt.u.CreateProcessInfo.hProcess, nullptr, filename, ARRAYSIZE(filename)));

      if (hasName)
        printf("New Process created with ProcessId %" PRIu32 " ('%s').\n", evnt.dwProcessId, filename);
      else
        printf("New Process created with ProcessId %" PRIu32 ".\n", evnt.dwProcessId);

      wchar_t filenameW[MAX_PATH];

      if (hasName && 0 != GetModuleFileNameExW(evnt.u.CreateProcessInfo.hProcess, nullptr, filenameW, ARRAYSIZE(filenameW)))
      {
        SProcessInfo procInfo;

        procInfo.modules.emplace_back();
        CopyString(procInfo.modules[0].filename, sizeof(procInfo.modules[0].filename), filenameW);
        procInfo.modules[0].nameOffset = PathFindFileNameW(procInfo.modules[0].filename) - procInfo.modules[0].filename;
        procInfo.modules[0].moduleIndex = 0;

        CComPtr<IDiaDataSource> pdbSource;

        if (GetPdbSource(&pdbSource, nullptr, filenameW, procInfo))
        {
          DWORD bytesRequired = 0;
          HMODULE modules[1024];

          do
          {
            if (0 == EnumProcessModules(procInfo.processHandle, modules, sizeof(modules), &bytesRequired) || bytesRequired < 8 * 1)
            {
              puts("Unable to Enumerate Process Modules for new sub process.");
              break;
            }

            const uint8_t *pBaseAddress = reinterpret_cast<const uint8_t *>(modules[0]);
            IMAGE_DOS_HEADER moduleHeader;
            size_t bytesRead = 0;

            if (!ReadProcessMemory(procInfo.processHandle, pBaseAddress, &moduleHeader, sizeof(moduleHeader), &bytesRead) || bytesRead != sizeof(moduleHeader))
            {
              puts("Failed to Read Module DOS Header for new sub process.");
              break;
            }

            IMAGE_NT_HEADERS ntHeader;

            if (!ReadProcessMemory(procInfo.processHandle, pBaseAddress + moduleHeader.e_lfanew, &ntHeader, sizeof(ntHeader), &bytesRead) || bytesRead != sizeof(ntHeader))
            {
              puts("Failed to Read Module NT Header for new sub process.");
              break;
            }

            procInfo.modules[0].moduleBaseAddress = (size_t)pBaseAddress;
            procInfo.modules[0].startAddress = ntHeader.OptionalHeader.BaseOfCode;
            procInfo.modules[0].endAddress = procInfo.modules[0].startAddress + (size_t)ntHeader.OptionalHeader.SizeOfCode;
            procInfo.modules[0].moduleEndAddress = procInfo.modules[0].moduleBaseAddress + procInfo.modules[0].endAddress;
            procInfo.minimalVirtualAddress = procInfo.modules[0].moduleBaseAddress;
            procInfo.maximalVirtualAddress = procInfo.modules[0].moduleEndAddress;

            // Place Main Thread in Threads.
            {
              SThreadRip mainThread;
              mainThread.handle = evnt.u.CreateProcessInfo.hThread;
              mainThread.threadId = GetThreadId(evnt.u.CreateProcessInfo.hThread);
              mainThread.lastRip = 0;

              procInfo.threads.emplace_back(mainThread);
            }

            //if (appInfo.procs_size == 0)
              appInfo.procs[appInfo.procs_size++] = std::move(procInfo);

          } while (0);
        }
      }
    }
    else if (!appInfo.procs[processIndex].hasName)
    {
      appInfo.procs[processIndex].hasName = (0 != GetModuleFileNameExA(evnt.u.CreateProcessInfo.hProcess, nullptr, appInfo.procs[processIndex].name, ARRAYSIZE(appInfo.procs[processIndex].name)));
    }

    break;
  }

  case EXIT_THREAD_DEBUG_EVENT:
  {
    for (size_t i = 0; i < appInfo.procs[processIndex].threads.size(); i++)
    {
      if (evnt.dwThreadId == appInfo.procs[processIndex].threads[i].threadId)
      {
        appInfo.procs[processIndex].threads.erase(appInfo.procs[processIndex].threads.begin() + i);
        break;
      }
    }

    break;
  }

  case EXIT_PROCESS_DEBUG_EVENT:
    FATAL("Unexpected `EXIT_PROCESS_DEBUG_EVENT`. Aborting.");
    break;

  case LOAD_DLL_DEBUG_EVENT:
  {
    wchar_t filename[MAX_PATH];
    bool hasFilename = false;

    if (_VerboseLogging)
      SetConsoleColor(CC_DarkGray, CC_Black);

    if (GetModuleFileName((HMODULE)evnt.u.LoadDll.lpBaseOfDll, filename, ARRAYSIZE(filename)))
    {
      if (_VerboseLogging)
        printf("Loaded DLL '%ws'.", filename);

      hasFilename = true;
    }
    else
    {
      char filenameA[MAX_PATH];
      size_t bytesRead = 0;

      if (evnt.u.LoadDll.lpImageName != nullptr)
      {
        void *pName = nullptr;

        if (ReadProcessMemory(appInfo.procs[processIndex].processHandle, evnt.u.LoadDll.lpImageName, &pName, sizeof(pName), &bytesRead) && bytesRead == sizeof(pName))
        {
          if (evnt.u.LoadDll.fUnicode)
          {
            if (ReadProcessMemory(appInfo.procs[processIndex].processHandle, pName, filename, sizeof(filename), &bytesRead))
              hasFilename = true;

            filename[ARRAYSIZE(filename) - 1] = L'\0';
          }
          else
          {
            if (ReadProcessMemory(appInfo.procs[processIndex].processHandle, pName, filenameA, sizeof(filenameA), &bytesRead))
            {
              filenameA[sizeof(filenameA) - 1] = '\0';

              if (0 < MultiByteToWideChar(CP_UTF8, 0, filenameA, sizeof(filenameA), filename, ARRAYSIZE(filename)))
                hasFilename = true;
            }

            filename[ARRAYSIZE(filename) - 1] = L'\0';
          }
        }
      }

      if (_VerboseLogging)
      {
        if (hasFilename)
          printf("Loaded Module '%ws' at 0x%" PRIX64 ".", filename, (size_t)evnt.u.LoadDll.lpBaseOfDll);
        else
          printf("Loaded Unknown Module at 0x%" PRIX64 ".", (size_t)evnt.u.LoadDll.lpBaseOfDll);
      }
    }

    {
      bool loaded = false;

      if (hasFilename && evnt.u.LoadDll.nDebugInfoSize != 0 && evnt.u.LoadDll.dwDebugInfoFileOffset != 0)
      {
        IMAGE_DOS_HEADER moduleHeader;
        IMAGE_NT_HEADERS ntHeader;
        size_t bytesRead = 0;

        if (!ReadProcessMemory(appInfo.procs[processIndex].processHandle, evnt.u.LoadDll.lpBaseOfDll, &moduleHeader, sizeof(moduleHeader), &bytesRead) || bytesRead != sizeof(moduleHeader) || !ReadProcessMemory(appInfo.procs[processIndex].processHandle, reinterpret_cast<const uint8_t *>(evnt.u.LoadDll.lpBaseOfDll) + moduleHeader.e_lfanew, &ntHeader, sizeof(ntHeader), &bytesRead) || bytesRead != sizeof(ntHeader))
        {
          if (_VerboseLogging)
            puts(" (Failed to load DOS / NT header)");
        }
        else
        {
          SModuleInfo info;
          CComPtr<IDiaDataSource> pdbSource;

          if (FAILED(CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&pdbSource)) || FAILED(pdbSource->loadDataForExe(filename, nullptr, nullptr)) || FAILED(pdbSource->openSession(&info.pdbSession)))
          {
            if (_VerboseLogging)
              puts(" (Failed to load PDB)");
          }
          else
          {
            CopyString(info.filename, sizeof(info.filename), filename);
            info.nameOffset = PathFindFileNameW(info.filename) - info.filename;
            info.moduleBaseAddress = (size_t)evnt.u.LoadDll.lpBaseOfDll;
            info.startAddress = ntHeader.OptionalHeader.BaseOfCode;
            info.endAddress = info.startAddress + (size_t)ntHeader.OptionalHeader.SizeOfCode;
            info.moduleEndAddress = info.moduleBaseAddress + info.endAddress;
            info.moduleIndex = _NextModuleIndex++;

            if (appInfo.procs[processIndex].minimalVirtualAddress > info.moduleBaseAddress)
              appInfo.procs[processIndex].minimalVirtualAddress = info.moduleBaseAddress;

            if (appInfo.procs[processIndex].maximalVirtualAddress < info.moduleEndAddress)
              appInfo.procs[processIndex].maximalVirtualAddress = info.moduleEndAddress;

            appInfo.procs[processIndex].modules.push_back(info);

            if (!_VerboseLogging)
              printf("Loaded DLL '%ws'.", filename);

            puts(" (Module Added)");

            loaded = true;
          }
        }
      }

      if (!loaded)
      {
        IMAGE_DOS_HEADER moduleHeader;
        IMAGE_NT_HEADERS ntHeader;
        size_t bytesRead = 0;

        if (!ReadProcessMemory(appInfo.procs[processIndex].processHandle, evnt.u.LoadDll.lpBaseOfDll, &moduleHeader, sizeof(moduleHeader), &bytesRead) || bytesRead != sizeof(moduleHeader) || !ReadProcessMemory(appInfo.procs[processIndex].processHandle, reinterpret_cast<const uint8_t *>(evnt.u.LoadDll.lpBaseOfDll) + moduleHeader.e_lfanew, &ntHeader, sizeof(ntHeader), &bytesRead) || bytesRead != sizeof(ntHeader))
        {
          if (_VerboseLogging)
            puts(" (Backup: Failed to load DOS / NT header)");
        }
        else
        {
          SNamedLibraryInfo info;
          CopyString(info.filename, sizeof(info.filename), filename);
          info.nameOffset = PathFindFileNameW(info.filename) - info.filename;
          info.moduleBaseAddress = (size_t)evnt.u.LoadDll.lpBaseOfDll;
          info.startAddress = ntHeader.OptionalHeader.BaseOfCode;
          info.endAddress = info.startAddress + (size_t)ntHeader.OptionalHeader.SizeOfCode;
          info.moduleEndAddress = info.moduleBaseAddress + info.endAddress;
          info.loaded = true;

          const IMAGE_EXPORT_DIRECTORY *pExports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(info.moduleBaseAddress + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
          IMAGE_EXPORT_DIRECTORY exports;

          if (!ReadProcessMemory(appInfo.procs[processIndex].processHandle, pExports, &exports, sizeof(exports), &bytesRead) || bytesRead != sizeof(exports))
          {
            if (_VerboseLogging)
              puts(" (Backup: Failed to read IMAGE_EXPORTS_DIRECTORY)");
          }
          else
          {
            const uint32_t *pFunctionNameOffsets = reinterpret_cast<const uint32_t *>(info.moduleBaseAddress + exports.AddressOfNames);
            const uint32_t *pFunctionAddressOffsets = reinterpret_cast<const uint32_t *>(info.moduleBaseAddress + exports.AddressOfFunctions);
            const uint16_t *pOrdinalOffsets = reinterpret_cast<const uint16_t *>(info.moduleBaseAddress + exports.AddressOfNameOrdinals);

            for (DWORD i = 0; i < exports.NumberOfNames; i++)
            {
              uint32_t nameOffset;
              uint16_t nameOrdinal;
              uint32_t functionAddressOffset;
              char functionName[1024];

              if (!ReadProcessMemory(appInfo.procs[processIndex].processHandle, pFunctionNameOffsets + i, &nameOffset, sizeof(nameOffset), &bytesRead) || bytesRead != sizeof(nameOffset) || !ReadProcessMemory(appInfo.procs[processIndex].processHandle, reinterpret_cast<const char *>(info.moduleBaseAddress + nameOffset), functionName, sizeof(functionName), &bytesRead) || bytesRead != sizeof(functionName) || !ReadProcessMemory(appInfo.procs[processIndex].processHandle, pOrdinalOffsets + i, &nameOrdinal, sizeof(nameOrdinal), &bytesRead) || bytesRead != sizeof(nameOrdinal) || !ReadProcessMemory(appInfo.procs[processIndex].processHandle, pFunctionAddressOffsets + nameOrdinal, &functionAddressOffset, sizeof(functionAddressOffset), &bytesRead) || bytesRead != sizeof(functionAddressOffset))
              {
                if (_VerboseLogging)
                  puts(" (Backup: Unexpected read failure)");

                break;
              }

              functionName[sizeof(functionName) - 1] = '\0';

              SLibraryFunction function;
              char functionNameUndecorated[1024];

              if (UnDecorateSymbolName(functionName, functionNameUndecorated, sizeof(functionNameUndecorated), UNDNAME_NO_ACCESS_SPECIFIERS | UNDNAME_NO_ALLOCATION_MODEL))
                CopyString(function.name, sizeof(function.name), functionNameUndecorated);
              else
                CopyString(function.name, sizeof(function.name), functionName);

              function.virtualAddressOffset = (size_t)functionAddressOffset;

              info.functions.emplace_back(function);
            }

            std::sort(info.functions.begin(), info.functions.end());

            if (appInfo.procs[processIndex].minimalIndirectVirtualAddress > info.moduleBaseAddress)
              appInfo.procs[processIndex].minimalIndirectVirtualAddress = info.moduleBaseAddress;

            if (appInfo.procs[processIndex].maximalIndirectVirtualAddress < info.moduleEndAddress)
              appInfo.procs[processIndex].maximalIndirectVirtualAddress = info.moduleEndAddress;

            appInfo.procs[processIndex].foreignModules.emplace_back(info);

            if (_VerboseLogging)
              printf(" (%" PRIu64 " entries extracted)\n", info.functions.size());
          }
        }
      }
    }

    SetConsoleColor(CC_BrightGray, CC_Black);

    break;
  }

  case UNLOAD_DLL_DEBUG_EVENT:
  {
    wchar_t filename[MAX_PATH];

    if (_VerboseLogging)
      SetConsoleColor(CC_DarkGray, CC_Black);

    if (GetModuleFileName((HMODULE)evnt.u.LoadDll.lpBaseOfDll, filename, ARRAYSIZE(filename)))
    {
      if (_VerboseLogging)
        printf("Unloaded DLL '%ws'.", filename);

      bool found = false;

      for (size_t i = 0; i < appInfo.procs[processIndex].modules.size(); i++)
      {
        if (appInfo.procs[processIndex].modules[i].moduleBaseAddress == (size_t)evnt.u.UnloadDll.lpBaseOfDll)
        {
          if (!_VerboseLogging)
            printf("Unloaded DLL '%ws'.", filename);

          puts(" (Module Archived)");

          appInfo.procs[processIndex].inactiveModules.push_back(appInfo.procs[processIndex].modules[i]);
          appInfo.procs[processIndex].modules.erase(appInfo.procs[processIndex].modules.begin() + i);
          break;
        }

        if (!found && _VerboseLogging)
          puts(" (Skipped)");
      }

      if (!found)
      {
        for (auto &_module : appInfo.procs[processIndex].foreignModules)
          if (_module.loaded && _module.moduleBaseAddress == (size_t)evnt.u.UnloadDll.lpBaseOfDll)
            _module.loaded = false;
      }
    }
    else
    {
      if (_VerboseLogging)
        printf("Unloaded Unknown Module at 0x%" PRIX64 ".\n", (size_t)evnt.u.LoadDll.lpBaseOfDll);
    }

    if (_VerboseLogging)
      SetConsoleColor(CC_BrightGray, CC_Black);

    break;
  }
  }
}

////////////////////////////////////////////////////////////////////////////////

SEvalResult EvaluateSession(SAppInfo &appInfo, _Inout_ SProcessProfileResult &perfSession, const size_t startIndex, const size_t endIndex, const size_t indirectStartIndex, const size_t indirectEndIndex)
{
  size_t processIndex = 0;

  for (; processIndex < appInfo.procs_size; processIndex++)
    if (appInfo.procs[processIndex].processId == perfSession.processId)
      break;

  FATAL_IF(processIndex == appInfo.procs_size, "Invalid Process Selected.");

  SEvalResult ret;

  printf("Evaluating %" PRIu64 " selected samples...\n", endIndex - startIndex);

  std::sort(perfSession.directHits.begin() + startIndex, perfSession.directHits.begin() + endIndex);

  if (appInfo.procs[processIndex].inactiveModules.size() > 0)
  {
    appInfo.procs[processIndex].modules.insert(appInfo.procs[processIndex].modules.begin(), std::make_move_iterator(begin(appInfo.procs[processIndex].inactiveModules)), std::make_move_iterator(end(appInfo.procs[processIndex].inactiveModules)));
    std::sort(appInfo.procs[processIndex].modules.begin(), appInfo.procs[processIndex].modules.end());
  }

  size_t i = startIndex;

  for (size_t moduleIndex = 0; moduleIndex < appInfo.procs[processIndex].modules.size(); moduleIndex++)
  {
    CComPtr<IDiaEnumSymbolsByAddr> enumByAddr;

    if (FAILED(appInfo.procs[processIndex].modules[moduleIndex].pdbSession->getSymbolsByAddr(&enumByAddr)))
    {
      printf("Failed to get Iterator for Module '%ws'. Skipping Module.\n", appInfo.procs[processIndex].modules[moduleIndex].filename + appInfo.procs[processIndex].modules[moduleIndex].nameOffset);
      continue;
    }

    for (; i < endIndex; i++)
    {
      const SProfileHit hit = perfSession.directHits[i];

      if (hit.GetModule() != (uint8_t)moduleIndex)
        break;

      CComPtr<IDiaSymbol> symbol;

      if (FAILED(enumByAddr->symbolByAddr(1, (DWORD)(hit.GetAddress() - appInfo.procs[processIndex].modules[moduleIndex].startAddress), &symbol)) || symbol == nullptr)
        continue;

      DWORD virtualAddress;
      wchar_t *symbolName = nullptr;
      size_t length;

      if (FAILED(symbol->get_relativeVirtualAddress(&virtualAddress)) || FAILED(symbol->get_name(&symbolName)) || FAILED(symbol->get_length(&length)))
      {
        if (symbolName != nullptr)
          SysFreeString(symbolName);

        continue;
      }

      SPerfEval func;
      func.symbolStartPos = virtualAddress;
      func.symbolEndPos = func.symbolStartPos + length;

      if (hit.GetAddress() < func.symbolStartPos)
        func.symbolStartPos = hit.GetAddress();

      if (hit.GetAddress() > func.symbolEndPos)
        func.symbolEndPos = hit.GetAddress();

      func.moduleIndex = (uint8_t)hit.GetModule();

      CopyString(func.symbolName, sizeof(func.symbolName), appInfo.procs[processIndex].modules[func.moduleIndex].filename + appInfo.procs[processIndex].modules[func.moduleIndex].nameOffset);
      StrCatBuffW(func.symbolName, L" - ", sizeof(func.symbolName));
      StrCatBuffW(func.symbolName, symbolName, sizeof(func.symbolName));
      SysFreeString(symbolName);

      if (FAILED(symbol->get_addressSection(&func.sector)))
        func.sector = (DWORD)-1;

      if (FAILED(symbol->get_addressOffset(&func.offset)))
        func.offset = (DWORD)-1;

      func.hitsOffset.emplace_back((uint32_t)(hit.GetAddress() - func.symbolStartPos));

      while (endIndex > i + 1)
      {
        const SProfileHit nextHit = perfSession.directHits[i + 1];

        if (nextHit.GetModule() != hit.GetModule() || nextHit.GetAddress() > func.symbolEndPos)
        {
          DWORD nextVirtualAddress = 0;
          CComPtr<IDiaSymbol> nextSymbol;

          if (SUCCEEDED(enumByAddr->symbolByAddr(1, (DWORD)(nextHit.GetAddress() - appInfo.procs[processIndex].modules[moduleIndex].startAddress), &nextSymbol)) && nextSymbol != nullptr && SUCCEEDED(nextSymbol->get_relativeVirtualAddress(&nextVirtualAddress)) && nextVirtualAddress == virtualAddress)
          {
            func.symbolEndPos = nextHit.GetAddress();
          }
          else
          {
            break;
          }
        }

        i++;
        func.hitsOffset.emplace_back((uint32_t)(nextHit.GetAddress() - func.symbolStartPos));
      }

      ret.eval.emplace_back(std::move(func));
    }
  }

  std::sort(perfSession.indirectHits.begin() + indirectStartIndex, perfSession.indirectHits.begin() + indirectEndIndex, SortByForeignModule);

  i = indirectStartIndex;

  for (size_t foreignModuleIndex = 0; foreignModuleIndex < appInfo.procs[processIndex].foreignModules.size(); foreignModuleIndex++)
  {
    size_t functionIndex = 0;

    for (; i < indirectEndIndex; i++)
    {
      SProfileIndirectHit &hit = perfSession.indirectHits[i];

      if (hit.GetForeignModule() != (uint8_t)foreignModuleIndex)
        break;

      size_t lastOffset = (size_t)-1;

      for (; functionIndex < appInfo.procs[processIndex].foreignModules[foreignModuleIndex].functions.size(); functionIndex++)
      {
        const auto &function = appInfo.procs[processIndex].foreignModules[foreignModuleIndex].functions[functionIndex];

        if (function.virtualAddressOffset < hit.GetAddress())
          lastOffset = hit.GetAddress() - function.virtualAddressOffset;
        else
          break;
      }

      if (lastOffset == (size_t)-1)
      {
        hit.ToFunctionOffset(hit.GetAddress(), 0xFFFF);
      }
      else
      {
        functionIndex--;
        hit.ToFunctionOffset(lastOffset, functionIndex);
      }
    }
  }

  std::sort(perfSession.indirectHits.begin() + indirectStartIndex, perfSession.indirectHits.begin() + indirectEndIndex, SortByOwnedModule);

  i = indirectStartIndex;
  size_t funcEvalIndex = 0;

  for (; i < indirectEndIndex; i++)
  {
    // Find Starting Module.
    {
      const SProfileIndirectHit &hit = perfSession.indirectHits[i];

      while (funcEvalIndex < ret.eval.size() && (ret.eval[funcEvalIndex].moduleIndex < hit.ownedModuleHit.GetModule() || hit.ownedModuleHit.GetAddress() < ret.eval[funcEvalIndex].symbolStartPos))
        funcEvalIndex++;

      if (funcEvalIndex >= ret.eval.size())
        break;
    }

    // Find Starting Indirect Hit.
    {
      const auto &func = ret.eval[funcEvalIndex];

      while (i < indirectEndIndex && (perfSession.indirectHits[i].ownedModuleHit.GetModule() < func.moduleIndex || perfSession.indirectHits[i].ownedModuleHit.GetAddress() < func.symbolStartPos))
        i++;

      if (i >= indirectEndIndex)
        break;
    }

    // Now ret.eval[funcEvalIndex].moduleIndex matches the hit moduleIndex.
    const SProfileIndirectHit &hit = perfSession.indirectHits[i];

    do
    {
      auto &func = ret.eval[funcEvalIndex];

      if (hit.ownedModuleHit.GetAddress() <= func.symbolEndPos)
      {
        bool found = false;

        // Does the indirectly hit function already contain a reference to this library function?
        for (auto &_indirectHit : func.foreignHits)
        {
          // Yes? Then increment the count.
          if (_indirectHit.foreignModuleIndex == hit.GetForeignModule() && _indirectHit.functionIndex == hit.GetFunctionIndex() && _indirectHit.offset == hit.ownedModuleHit.GetAddress() - func.symbolStartPos)
          {
            _indirectHit.count++;
            found = true;
            break;
          }
        }

        // No? Then add one!
        if (!found)
        {
          SForeignHitEval fhit;
          fhit.offset = (uint32_t)(hit.ownedModuleHit.GetAddress() - func.symbolStartPos);
          fhit.count = 1;
          fhit.foreignModuleIndex = (uint8_t)(hit.GetForeignModule());
          fhit.functionIndex = (uint16_t)hit.GetFunctionIndex();

          func.foreignHits.emplace_back(fhit);
        }

        break;
      }

      funcEvalIndex++;

    } while (funcEvalIndex < ret.eval.size());
  }

  for (auto &_func : ret.eval)
    if (_func.foreignHits.size() != 0)
      std::sort(_func.foreignHits.begin(), _func.foreignHits.end());

  return ret;
}

////////////////////////////////////////////////////////////////////////////////

bool GetDetailedEvaluation(_In_ CComPtr<IDiaSession> &session, _In_ const SPerfEval &function, _Inout_ SFuncEval &funcEval)
{
  funcEval.files.clear();
  funcEval.lines.clear();

  ERROR_RETURN_IF(function.sector == (DWORD)-1 || function.offset == (DWORD)-1, "Unknown Sector or Offset for this Function.");

  for (size_t i = 0; i < function.hitsOffset.size(); i++)
  {
    CComPtr<IDiaEnumLineNumbers> lineNumEnum;

    if (FAILED(session->findLinesByAddr(function.sector, function.offset + function.hitsOffset[i], 1, &lineNumEnum)))
      continue;

    CComPtr<IDiaLineNumber> lineNumber;

    ULONG fetched;

    if (FAILED(lineNumEnum->Next(1, &lineNumber, &fetched)) || fetched == 0)
      continue;

    DWORD sourceFileId;

    if (FAILED(lineNumber->get_sourceFileId(&sourceFileId)))
      continue;

    uint32_t fileIndex = 0;

    for (const auto &_file : funcEval.files)
    {
      if (_file.sourceFileId == sourceFileId)
        break;

      fileIndex++;
    }

    if (fileIndex == funcEval.files.size())
    {
      SSourceFile file;
      file.sourceFileId = sourceFileId;

      CComPtr<IDiaSourceFile> sourceFile;

      if (FAILED(lineNumber->get_sourceFile(&sourceFile)))
        continue;

      wchar_t *sourceFileName = nullptr;

      if (SUCCEEDED(sourceFile->get_fileName(&sourceFileName)))
        CopyString(file.filename, sizeof(file.filename), sourceFileName);

      if (sourceFileName != nullptr)
        SysFreeString(sourceFileName);

      funcEval.files.emplace_back(file);
    }

    DWORD line = 0;

    if (FAILED(lineNumber->get_lineNumber(&line)))
      continue;

    size_t address;

    if (FAILED(lineNumber->get_virtualAddress(&address)))
      address = function.hitsOffset[i];
    else if (address > function.hitsOffset[i] + function.symbolStartPos)
      address = function.hitsOffset[i];

    DWORD length;

    if (FAILED(lineNumber->get_length(&length)))
      length = (DWORD)(function.hitsOffset[i] + function.symbolStartPos - address);

    const size_t endAddress = address + length;

    size_t count = 1;

    while (function.hitsOffset.size() > i + 1 && function.hitsOffset[i + 1] + function.symbolStartPos < endAddress)
    {
      count++;
      i++;
    }

    funcEval.lines.emplace_back(fileIndex, line, address, endAddress, count);
  }

  std::sort(funcEval.lines.begin(), funcEval.lines.end());

  return true;
}

////////////////////////////////////////////////////////////////////////////////

bool LoadBinary(SAppInfo &appInfo, const size_t processIndex, const size_t moduleIndex)
{
  if (appInfo.procs[processIndex].modules[moduleIndex].pBinary != nullptr)
    return appInfo.procs[processIndex].modules[moduleIndex].hasDisasm;

  FILE *pFile = _wfopen(appInfo.procs[processIndex].modules[moduleIndex].filename, L"rb");
  ERROR_RETURN_IF(pFile == nullptr, "Failed to open binary file.");

  auto defer_fclose = std::unique_ptr<FILE, int (*)(FILE *)>(pFile, fclose);

  fseek(pFile, 0, SEEK_END);
  const int64_t expectedFileSize = _ftelli64(pFile);
  fseek(pFile, 0, SEEK_SET);

  uint8_t *fileContents = reinterpret_cast<uint8_t *>(malloc(expectedFileSize));
  ERROR_RETURN_IF(fileContents == nullptr, "Failed to allocate memory.");

  const size_t fileSize = fread(fileContents, 1, expectedFileSize, pFile);

  if ((size_t)expectedFileSize != fileSize)
  {
    free(fileContents);
    ERROR_RETURN_IF(true, "Failed to read file.");
  }

  appInfo.procs[processIndex].modules[moduleIndex].pBinary = fileContents;
  appInfo.procs[processIndex].modules[moduleIndex].binaryLength = fileSize;

  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisDecoderInit(&appInfo.procs[processIndex].modules[moduleIndex].decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)), "Failed to initialize disassembler.");
  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisFormatterInit(&appInfo.procs[processIndex].modules[moduleIndex].formatter, ZYDIS_FORMATTER_STYLE_INTEL)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.procs[processIndex].modules[moduleIndex].formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.procs[processIndex].modules[moduleIndex].formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)), "Failed to initialize instruction formatter.");

  appInfo.procs[processIndex].modules[moduleIndex].hasDisasm = true;

  return true;
}

////////////////////////////////////////////////////////////////////////////////

// Returns the next start index, when displaying incrementally.
size_t DisplayOffsetIndirectHits(SAppInfo &appInfo, const size_t processIndex, const SPerfEval &function, const size_t startOffset, const size_t endOffset, const size_t indirectHitsStartIndex)
{
  for (size_t i = indirectHitsStartIndex; i < function.foreignHits.size(); i++)
  {
    const auto &foreignHit = function.foreignHits[i];
    const size_t foreignHitAddress = function.symbolStartPos + foreignHit.offset;

    if (foreignHitAddress > endOffset) // Yes, this is technically off by one, however this appears to be correct.
    {
      return i;
    }
    else if (foreignHitAddress >= startOffset)
    {
      SetConsoleColor(CC_BrightGreen, CC_Black);

      printf("           | % 5" PRIu64 " | INDIRECT CALL AT %ws - ", foreignHit.count, appInfo.procs[processIndex].foreignModules[foreignHit.foreignModuleIndex].filename + appInfo.procs[processIndex].foreignModules[foreignHit.foreignModuleIndex].nameOffset);

      if (foreignHit.functionIndex == 0xFFFF)
        printf("<UNKNOWN_FUNCTION>\n");
      else
        puts(appInfo.procs[processIndex].foreignModules[foreignHit.foreignModuleIndex].functions[foreignHit.functionIndex].name);
    }
  }

  return function.foreignHits.size();
}

////////////////////////////////////////////////////////////////////////////////

uint64_t _GetAddressFromOperand(const ZydisDecodedInstruction *pInstruction, const size_t operatorIndex, const size_t virtualAddress)
{
  uint64_t ptr = 0;

  switch (pInstruction->operands[operatorIndex].type)
  {
  case ZYDIS_OPERAND_TYPE_IMMEDIATE:
  {
    if (pInstruction->mnemonic == ZYDIS_MNEMONIC_MOV || pInstruction->mnemonic == ZYDIS_MNEMONIC_LEA)
      return (uint64_t)-1;

    if (pInstruction->operands[operatorIndex].imm.is_relative)
      ptr = (uint64_t)(virtualAddress + pInstruction->length);

    if (pInstruction->operands[operatorIndex].imm.is_signed)
      ptr = (int64_t)ptr + (int64_t)(pInstruction->operands[operatorIndex].imm.value.s);
    else
      ptr = (uint64_t)(pInstruction->operands[operatorIndex].imm.value.u);

    break;
  }

  case ZYDIS_OPERAND_TYPE_MEMORY:
  {
    if (pInstruction->operands[operatorIndex].mem.segment != ZYDIS_REGISTER_DS)
      return (uint64_t)-1;

    if (pInstruction->operands[operatorIndex].mem.base == ZYDIS_REGISTER_RIP)
      ptr = virtualAddress + pInstruction->length + pInstruction->operands[operatorIndex].mem.disp.value;
    else
      return (uint64_t)-1;

    break;
  }

  case ZYDIS_OPERAND_TYPE_POINTER:
  {
    if (pInstruction->operands[operatorIndex].ptr.segment != ZYDIS_REGISTER_DS)
      return (uint64_t)-1;

    ptr = virtualAddress + pInstruction->length + pInstruction->operands[operatorIndex].ptr.offset; // TODO: Is this valid?
  }
  }
  return ptr;
}

bool InstrumentDisassembly(SAppInfo &appInfo, const size_t processIndex, const SPerfEval &function, const size_t startAddress, const size_t endAddress, const SFuncLineOptions &options, const size_t maxLineHits, size_t *pIndirectHitsStartIndex)
{
  size_t virtualAddress = startAddress;
  ZydisDecodedInstruction instruction;
  char disasmBuffer[1024] = {};

  const uint8_t *pBinaryAtAddress = appInfo.procs[processIndex].modules[function.moduleIndex].pBinary;

  IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pBinaryAtAddress;
  IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *)(pBinaryAtAddress + pDosHeader->e_lfanew);
  IMAGE_SECTION_HEADER *pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

  const uint8_t *pCode = pBinaryAtAddress + pSectionHeader[0].PointerToRawData;
  const uint64_t virtualStartAddress = pSectionHeader[0].VirtualAddress;

  pBinaryAtAddress = pCode + startAddress - virtualStartAddress;

  size_t hitIndex = 0;
  const size_t expensiveThreshold = (size_t)(maxLineHits * options.expensiveAsmThreshold);

  SetConsoleColor(CC_DarkCyan, CC_Black);
  const size_t width = GetConsoleWidth();

  for (size_t i = 0; i < (width - 1); i++)
    putc('-', stdout);

  putc('\n', stdout);

  while (virtualAddress < endAddress)
  {
    ERROR_RETURN_IF(!(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&appInfo.procs[processIndex].modules[function.moduleIndex].decoder, pBinaryAtAddress, endAddress - virtualAddress + 32 /* Just to force decoding the last instruction */, &instruction))), "Invalid Instruction at 0x%" PRIX64 ".", virtualAddress);
    ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&appInfo.procs[processIndex].modules[function.moduleIndex].formatter, &instruction, disasmBuffer, sizeof(disasmBuffer), virtualAddress)), "Failed to Format Instruction at 0x%" PRIX64 ".", virtualAddress);

    size_t hits = 0;
    const size_t virtualAddressOffset = virtualAddress - function.symbolStartPos;

    while (hitIndex < function.hitsOffset.size())
    {
      if (function.hitsOffset[hitIndex] > virtualAddressOffset + instruction.length) // Yes, this is technically off by one, however this appears to be correct.
        break;
      else if (function.hitsOffset[hitIndex] >= virtualAddressOffset)
        hits++;

      hitIndex++;
    }

    SetConsoleColor(hits > expensiveThreshold ? CC_BrightCyan : CC_DarkCyan, CC_Black);

    if (hits > 0)
      printf("0x%08" PRIX64 " | % 5" PRIu64 " | %s", virtualAddress, hits, disasmBuffer);
    else
      printf("0x%08" PRIX64 " |       | %s", virtualAddress, disasmBuffer);

    switch (instruction.mnemonic)
    {
    case ZYDIS_MNEMONIC_CALL:
    case ZYDIS_MNEMONIC_JMP:
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JKNZD:
    case ZYDIS_MNEMONIC_JKZD:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JNZ:
    {
      const uint64_t operandAddress = _GetAddressFromOperand(&instruction, 0, virtualAddress);

      if (operandAddress != (uint64_t)-1)
      {
        const uint64_t mappedAddress = operandAddress + appInfo.procs[processIndex].modules[function.moduleIndex].moduleBaseAddress;

        size_t moduleIndex = (size_t)-1;
        bool found = false;

        if (mappedAddress >= appInfo.procs[processIndex].minimalVirtualAddress || mappedAddress < appInfo.procs[processIndex].maximalVirtualAddress)
        {
          for (const auto &_module : appInfo.procs[processIndex].modules)
          {
            ++moduleIndex;

            if (mappedAddress >= _module.moduleBaseAddress && mappedAddress < _module.moduleEndAddress)
            {
              CComPtr<IDiaEnumSymbolsByAddr> enumerator;
              CComPtr<IDiaSymbol> symbol;
              wchar_t *symbolName = nullptr;
              size_t symbolStartAddress = 0;

              if (SUCCEEDED(_module.pdbSession->getSymbolsByAddr(&enumerator)) && SUCCEEDED(enumerator->symbolByAddr(1, (DWORD)(mappedAddress - _module.moduleBaseAddress - _module.startAddress), &symbol)) && SUCCEEDED(symbol->get_name(&symbolName)) && SUCCEEDED(symbol->get_virtualAddress(&symbolStartAddress)))
              {
                if (moduleIndex != (size_t)function.moduleIndex)
                  printf("\t\t\t\t[%ws - ", _module.filename + _module.nameOffset);
                else
                  printf("\t\t\t\t[");

                if (symbolStartAddress == function.symbolStartPos && moduleIndex == (size_t)function.moduleIndex)
                {
                  printf("%+" PRIi64 " (0x%08" PRIX64 ")]", operandAddress - virtualAddress, operandAddress);
                }
                else
                {
                  const size_t offset = (mappedAddress - _module.moduleBaseAddress) - symbolStartAddress;

                  if (offset == 0)
                    printf("%ws]", symbolName);
                  else
                    printf("%ws + 0x%" PRIX64 "]", symbolName, offset);
                }
              }
              else
              {
                printf("\t\t\t\t[%ws - <UNKNOWN_FUNCTION>]", _module.filename + _module.nameOffset);
              }

              if (symbolName != nullptr)
                SysFreeString(symbolName);

              break;
            }
          }
        }

        if (!found && mappedAddress >= appInfo.procs[processIndex].minimalIndirectVirtualAddress && mappedAddress < appInfo.procs[processIndex].maximalIndirectVirtualAddress)
        {
          for (const auto &_module : appInfo.procs[processIndex].foreignModules)
          {
            if (mappedAddress >= _module.moduleBaseAddress && mappedAddress < _module.moduleEndAddress)
            {
              printf("\t\t\t\t[%ws - ", _module.filename + _module.nameOffset);
              size_t lastFunctionIndex = (size_t)-1;
              size_t lastOffset = (size_t)-1;

              for (const auto &_symbol : _module.functions)
              {
                const size_t mappedStartAddress = _symbol.virtualAddressOffset + _module.moduleBaseAddress;

                if (_symbol.virtualAddressOffset <= mappedStartAddress)
                  lastOffset = mappedAddress - mappedStartAddress;
                else
                  break;

                lastFunctionIndex++;
              }

              if (lastOffset == (size_t)-1)
                printf("<UNKNOWN_FUNCTION>]");
              else if (lastOffset == 0)
                printf("%s]", _module.functions[lastFunctionIndex].name);
              else
                printf("%s +%" PRIu64 "]", _module.functions[lastFunctionIndex].name, lastOffset);

              break;
            }
          }
        }
      }

      break;
    }
    }

    puts("");

    *pIndirectHitsStartIndex = DisplayOffsetIndirectHits(appInfo, processIndex, function, virtualAddress, virtualAddress + instruction.length, *pIndirectHitsStartIndex);

    virtualAddress += instruction.length;
    pBinaryAtAddress += instruction.length;
  }

  SetConsoleColor(CC_DarkCyan, CC_Black);

  for (size_t i = 0; i < (width - 1); i++)
    putc('-', stdout);

  putc('\n', stdout);

  return true;
}

bool InstrumentFunctionDisassembly(SAppInfo &appInfo, const size_t processIndex, const SPerfEval &function, const SFuncLineOptions &options)
{
  size_t maxHit = 0;
  size_t currentHits = 0;
  uint32_t currentOffset = 0;

  for (const auto &_hit : function.hitsOffset)
  {
    if (_hit != currentOffset)
    {
      maxHit = max(maxHit, currentHits);

      currentHits = 0;
      currentOffset = _hit;
    }

    currentHits++;
  }

  maxHit = max(maxHit, currentHits);
  size_t indirectHitStartIndex = 0;

  const size_t startAddress = function.symbolStartPos + (function.hitsOffset.size() ? function.hitsOffset[0] : 0);
  const size_t endAddress = (function.hitsOffset.size() ? min(function.symbolStartPos + function.hitsOffset[function.hitsOffset.size() - 1] + 16, function.symbolEndPos) : function.symbolEndPos) + 1; // just to even decode single instructions.

  const bool result = InstrumentDisassembly(appInfo, processIndex, function, startAddress, endAddress, options, maxHit, &indirectHitStartIndex);

  SetConsoleColor(CC_BrightGray, CC_Black);

  return result;
}

////////////////////////////////////////////////////////////////////////////////

bool InstrumentFunctionWithSource(SAppInfo &appInfo, const size_t processIndex, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options)
{
  ERROR_RETURN_IF(evaluation.eval.size() <= index, "Invalid Index.");

  const SPerfEval &function = evaluation.eval[index];
  const bool showDisasm = options.disasmExpensiveLines && LoadBinary(appInfo, processIndex, function.moduleIndex);

  printf("\nDetails for '%ws':\n\n", function.symbolName);

  SFuncEval lineEval;

  if (!GetDetailedEvaluation(appInfo.procs[processIndex].modules[function.moduleIndex].pdbSession, function, lineEval) || lineEval.lines.size() == 0)
  {
    puts("Failed to retrieve detailed evaluation.");

    if (showDisasm)
      InstrumentFunctionDisassembly(appInfo, processIndex, function, options);
  }
  else
  {
    size_t maximumLineHits = 0;

    for (const auto &_line : lineEval.lines)
      if (_line.hits > maximumLineHits)
        maximumLineHits = _line.hits;

    const size_t expensiveThreshold = (size_t)(maximumLineHits * options.expensiveLineThreshold);
    const size_t relevantThreshold = (size_t)(maximumLineHits * options.relevantLineThreshold);
    const size_t disasmThreshold = max((size_t)(maximumLineHits * options.disasmLineThreshold), options.minAsmSamples);

    bool failedFileDisasmShown = false;

    for (size_t i = 0; i < lineEval.lines.size(); i++)
    {
      const size_t fileIndex = lineEval.lines[i].fileIndex;
      constexpr size_t extraLines = 5;
      size_t targetLine = max(1, (lineEval.lines[i].line, lineEval.lines[i].line - extraLines)); // To prevent buffer overflows.

      FILE *pFile = _wfopen(lineEval.files[fileIndex].filename, L"rb");

      if (pFile == nullptr)
      {
        printf("Failed to read file '%ws'.\n", lineEval.files[fileIndex].filename);

        if (showDisasm && !failedFileDisasmShown)
        {
          InstrumentFunctionDisassembly(appInfo, processIndex, function, options);
          failedFileDisasmShown = true;
        }

        while (lineEval.lines.size() > i + 1 && lineEval.lines[i + 1].fileIndex == fileIndex)
          i++;

        continue;
      }

      printf("\nFile '%ws'.\n\n", lineEval.files[fileIndex].filename);

      auto defer_fclose = std::unique_ptr<FILE, int (*)(FILE *)>(pFile, fclose);

      fseek(pFile, 0, SEEK_END);
      const int64_t expectedFileSize = _ftelli64(pFile);
      fseek(pFile, 0, SEEK_SET);

      ERROR_CONTINUE_IF(expectedFileSize <= 0, "Invalid File Size.");

      char *fileContents = reinterpret_cast<char *>(malloc(expectedFileSize + 1));
      ERROR_CONTINUE_IF(fileContents == nullptr, "Failed to allocate memory.");

      auto defer_free = std::unique_ptr<char, void (*)(void *)>(fileContents, free);

      const size_t fileSize = fread(fileContents, 1, expectedFileSize, pFile);
      ERROR_CONTINUE_IF((size_t)expectedFileSize != fileSize, "Failed to read file.");
      fileContents[fileSize] = '\0';

      // Replace New Lines with '\0' to simplify printing lines.
      for (size_t j = 0; j < fileSize; j++)
        if (fileContents[j] == '\n')
          fileContents[j] = '\0';

      size_t currentLine = 1;
      size_t offset = 0;

      // Trim Lines.
      while (offset < fileSize)
      {
        if (currentLine == targetLine)
          break;

        offset += strlen(fileContents + offset) + 1;
        currentLine++;
      }

      ERROR_CONTINUE_IF(offset >= fileSize, "Unexpected End Of File.");

      targetLine = lineEval.lines[i].line;

      SetConsoleColor(CC_DarkGray, CC_Black);

      // Print Empty Lines.
      while (currentLine < targetLine && offset < fileSize)
      {
        printf("# % 8" PRIu64 " |       | %s\n", currentLine, fileContents + offset);

        offset += strlen(fileContents + offset) + 1;
        currentLine++;
      }

      ERROR_CONTINUE_IF(offset >= fileSize, "Unexpected End Of File.");

      SetConsoleColor(lineEval.lines[i].hits > expensiveThreshold ? CC_BrightRed : (lineEval.lines[i].hits > relevantThreshold ? CC_BrightYellow : CC_BrightGray), CC_Black);

      size_t indirectHitsStartIndex = 0;

      // Print Line With Hits.
      {
        printf("# % 8" PRIu64 " | % 5" PRIu64 " | %s\n", currentLine, lineEval.lines[i].hits, fileContents + offset);

        if (showDisasm && lineEval.lines[i].hits > disasmThreshold)
          InstrumentDisassembly(appInfo, processIndex, function, lineEval.lines[i].startAddress, lineEval.lines[i].endAddress, options, maximumLineHits, &indirectHitsStartIndex);
        else
          indirectHitsStartIndex = DisplayOffsetIndirectHits(appInfo, processIndex, function, lineEval.lines[i].startAddress, lineEval.lines[i].endAddress, indirectHitsStartIndex);

        offset += strlen(fileContents + offset) + 1;
        currentLine++;
      }

      while (lineEval.lines.size() > i + 1 && lineEval.lines[i + 1].fileIndex == fileIndex)
      {
        targetLine = lineEval.lines[i + 1].line;
        i++;

        SetConsoleColor(CC_DarkGray, CC_Black);

        // Print Empty Lines.
        while (currentLine < targetLine && offset < fileSize)
        {
          printf("# % 8" PRIu64 " |       | %s\n", currentLine, fileContents + offset);

          offset += strlen(fileContents + offset) + 1;
          currentLine++;
        }

        ERROR_CONTINUE_IF(offset >= fileSize, "Unexpected End Of File.");

        SetConsoleColor(lineEval.lines[i].hits > expensiveThreshold ? CC_BrightRed : (lineEval.lines[i].hits > relevantThreshold ? CC_BrightYellow : CC_BrightGray), CC_Black);

        // Print Line With Hits.
        {
          printf("# % 8" PRIu64 " | % 5" PRIu64 " | %s\n", currentLine, lineEval.lines[i].hits, fileContents + offset);

          if (showDisasm && lineEval.lines[i].hits > disasmThreshold)
            InstrumentDisassembly(appInfo, processIndex, function, lineEval.lines[i].startAddress, lineEval.lines[i].endAddress, options, maximumLineHits, &indirectHitsStartIndex);
          else
            indirectHitsStartIndex = DisplayOffsetIndirectHits(appInfo, processIndex, function, lineEval.lines[i].startAddress, lineEval.lines[i].endAddress, indirectHitsStartIndex);

          offset += strlen(fileContents + offset) + 1;
          currentLine++;
        }
      }

      targetLine += extraLines;

      SetConsoleColor(CC_DarkGray, CC_Black);

      while (currentLine < targetLine && offset < fileSize)
      {
        printf("# % 8" PRIu64 " |       | %s\n", currentLine, fileContents + offset);

        offset += strlen(fileContents + offset) + 1;
        currentLine++;
      }

      SetConsoleColor(CC_BrightGray, CC_Black);
    }
  }

  return true;
}
