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

struct SPerfEval
{
  wchar_t symbolName[384] = {};
  size_t symbolStartPos, symbolEndPos;
  DWORD sector, offset;
  uint8_t moduleIndex;

  std::vector<uint32_t> hitsOffset;

  inline bool operator < (const SPerfEval &other)
  {
    return hitsOffset.size() > other.hitsOffset.size();
  }
};

struct SModuleInfo
{
  size_t moduleBaseAddress;
  size_t moduleEndAddress;
  size_t startAddress;
  size_t endAddress;
  wchar_t filename[MAX_PATH] = {};
  wchar_t *moduleName = L"<UNKNOWN>";
  uint8_t *pBinary = nullptr;
  size_t binaryLength = 0;

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
  size_t samplingDelay = 0;
};

struct SProfileHit
{
  size_t packed;

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

struct SProfileResult
{
  std::deque<SProfileHit> directHits;
  std::vector<size_t> indexAtSecond;
};

struct SEvalResult
{
  std::vector<SPerfEval> eval;
};

struct SAppInfo
{
  std::vector<SThreadRip> threads;
  std::vector<SModuleInfo> modules;
  std::vector<SModuleInfo> inactiveModules;
  HANDLE processHandle;
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
  size_t minAsmSamples = 20;
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

SProfileResult ProfileApplicationNoStackTrace(SAppInfo &appInfo, const SProfileOptions &options);
void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt);
SEvalResult EvaluateSession(SAppInfo &appInfo, _Inout_ SProfileResult &perfSession, const size_t startIndex, const size_t endIndex);
bool GetDetailedEvaluation(_In_ CComPtr<IDiaSession> &session, _In_ const SPerfEval &function, _Inout_ SFuncEval &funcEval);
bool InstrumentFunctionWithSource(SAppInfo &appInfo, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options);
bool LoadBinary(SAppInfo &appInfo, const size_t moduleIndex);
bool InstrumentDisassembly(SAppInfo &appInfo, const SPerfEval &function, const size_t virtualStartAddress, const size_t virtualEndAddress, const SFuncLineOptions &options, const size_t maxLineHits);

////////////////////////////////////////////////////////////////////////////////

inline void CopyString(wchar_t *dst, const size_t dstSize, const wchar_t *src)
{
  const size_t textLength = min(dstSize - sizeof(wchar_t), wcslen(src) * sizeof(wchar_t));
  memcpy(dst, src, textLength);
  dst[textLength / sizeof(wchar_t)] = '\0';
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
  FATAL_IF(argc == 1, "\nUsage: silverpp <ExecutablePath>\n\n Optional Parameters:\n\n\t" CMD_PARAM_INDIRECT_HITS "\t\t | Trace external Samples back to the calling Function\n\t" CMD_PARAM_STACK_TRACE "\t\t\t | Capture Stack Traces for all Samples\n\t" CMD_PARAM_FAST_STACK_TRACE "\t\t | Fast (but possibly less accurate) Stack Traces\n\t" CMD_PARAM_FAVOR_ACCURACY "\t | Favor Sampling Accuracy over Application Performance\n\t" CMD_PARAM_SAMPLING_DELAY " <milliseconds>\t | Additional Sampling Delay (Improves performance at the cost of Samples)\n\t" CMD_PARAM_NO_DISASM "\t\t | Don't display disassembly for expensive lines\n\t" CMD_PARAM_VERBOSE "\t\t | Enable verbose logging\n\t" CMD_PARAM_ARGS_PASS_THROUGH " <Args>\t\t | Pass the remaining Arguments to the Application being profiled\n");

  wchar_t workingDirectory[MAX_PATH];
  FATAL_IF(0 == GetCurrentDirectory(ARRAYSIZE(workingDirectory), workingDirectory), "Failed to retrieve working directory. Aborting.");

  wchar_t *appPath = pArgv[1];
  wchar_t *pdbPath = nullptr;
  wchar_t *args = L"";

  bool analyzeStack = false;
  bool analyzeStackFast = false;
  bool indirectHits = false;
  bool favorAccuracy = false;
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

  SAppInfo appInfo;
  appInfo.modules.emplace_back();
  CopyString(appInfo.modules[0].filename, sizeof(appInfo.modules[0].filename), appPath);
  appInfo.modules[0].moduleName = PathFindFileNameW(appInfo.modules[0].filename);

  // Attempt to read PDB.
  {
    CComPtr<IDiaDataSource> pdbSource;

    FATAL_IF(FAILED(CoInitialize(nullptr)), "Failed to Initialize. Aborting.");

    FATAL_IF(FAILED(CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&pdbSource)), "Failed to retrieve an instance of the PDB Parser.");

    if (pdbPath == nullptr || FAILED(pdbSource->loadDataFromPdb(pdbPath)))
      if (FAILED(pdbSource->loadDataForExe(appPath, nullptr, nullptr)))
        FATAL("Failed to find pdb for the specified path.");

    FATAL_IF(FAILED(pdbSource->openSession(&appInfo.modules[0].pdbSession)), "Failed to Open Session.");
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

  appInfo.processHandle = processInfo.hProcess;

  // Start Debugging.
  {
    DEBUG_EVENT debugEvent;

    FATAL_IF(!WaitForDebugEvent(&debugEvent, 1000), "Failed to debug process. Aborting.");
    UpdateAppInfo(appInfo, debugEvent);
    FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE), "Failed to continue debugged process. Aborting.");
  }

  // Get Base Address of Main Module.
  {
    DWORD bytesRequired = 0;
    HMODULE modules[1024];
    DEBUG_EVENT debugEvent;
    
    while (0 == EnumProcessModules(appInfo.processHandle, modules, sizeof(modules), &bytesRequired) || bytesRequired < 8 * 3) // <module>, ntdll.dll, kernel32.dll
    {
      while (WaitForDebugEvent(&debugEvent, 0))
      {
        UpdateAppInfo(appInfo, debugEvent);
        FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE), "Failed to continue debugged process. Aborting.");
      }
    }

    FATAL_IF(!DebugBreakProcess(appInfo.processHandle), "Failed to pause process.");
    FATAL_IF(!WaitForDebugEvent(&debugEvent, 1000), "Failed to pause process. Aborting.");
    UpdateAppInfo(appInfo, debugEvent);

    const uint8_t *pBaseAddress = reinterpret_cast<const uint8_t *>(modules[0]);
    IMAGE_DOS_HEADER moduleHeader;
    size_t bytesRead = 0;
    FATAL_IF(!ReadProcessMemory(appInfo.processHandle, pBaseAddress, &moduleHeader, sizeof(moduleHeader), &bytesRead) || bytesRead != sizeof(moduleHeader), "Failed to Read Module DOS Header. Aborting.");

    IMAGE_NT_HEADERS ntHeader;
    FATAL_IF(!ReadProcessMemory(appInfo.processHandle, pBaseAddress + moduleHeader.e_lfanew, &ntHeader, sizeof(ntHeader), &bytesRead) || bytesRead != sizeof(ntHeader), "Failed to Read Module NT Header. Aborting.");

    appInfo.modules[0].moduleBaseAddress = (size_t)pBaseAddress;
    appInfo.modules[0].startAddress = ntHeader.OptionalHeader.BaseOfCode;
    appInfo.modules[0].endAddress = appInfo.modules[0].startAddress + (size_t)ntHeader.OptionalHeader.SizeOfCode;
    appInfo.modules[0].moduleEndAddress = appInfo.modules[0].moduleBaseAddress + appInfo.modules[0].endAddress;
    
    // Place Main Thread in Threads.
    {
      SThreadRip mainThread;
      mainThread.handle = processInfo.hThread;
      mainThread.threadId = processInfo.dwThreadId;
      mainThread.lastRip = 0;

      appInfo.threads.emplace_back(mainThread);
    }

    FATAL_IF(!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE), "Failed to continue debugged process. Aborting.");
  }

  if (!analyzeStack)
  {
    puts("Starting Profiling Loop...");

    SProfileOptions profileOptions;
    profileOptions.alwaysGetStackTrace = analyzeStack;
    profileOptions.getStackTraceOnExtern = indirectHits;
    profileOptions.fastStackTrace = analyzeStackFast;
    profileOptions.favorPerformance = !favorAccuracy;
    profileOptions.samplingDelay = samplingDelay;

    SProfileResult profileSession = ProfileApplicationNoStackTrace(appInfo, profileOptions);

    printf("Profiler Stopped.\nCaptured %" PRIu64 " direct hits.\n", profileSession.directHits.size());

    size_t startIndex = 0;
    size_t endIndex = 0;

    {
      constexpr size_t barWidth = 5;
      constexpr size_t barHeight = 8;

      const size_t width = min(GetConsoleWidth() / barWidth, profileSession.indexAtSecond.size());
      const size_t widthSkips = (profileSession.indexAtSecond.size() + width - 1) / width;

      size_t maxHeight = 0;
      size_t lastIndex = 0;

      struct Bar
      {
        size_t startIndex;
        size_t endIndex;
        size_t startSecond;
      };

      std::vector<Bar> bars;

      for (size_t i = widthSkips; i < profileSession.indexAtSecond.size(); i += widthSkips)
      {
        const size_t maxIndex = min(profileSession.indexAtSecond.size() - 1, i + widthSkips - 1);
        const size_t currentIndex = profileSession.indexAtSecond[maxIndex - 1];
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
        startIndex = 0;
      else
        startIndex = profileSession.indexAtSecond[min(second, profileSession.indexAtSecond.size() - 1)];

      puts("Select End Second: (0 to include everything)");

      if (1 != scanf("%" PRIu64 "", &second))
        second = 0;

      if (second == 0)
        endIndex = profileSession.directHits.size();
      else
        endIndex = profileSession.indexAtSecond[min(second, profileSession.indexAtSecond.size() - 1)];
    }

    if (startIndex >= endIndex)
      endIndex = profileSession.directHits.size();

    puts("Evaluating Profiling Data...");

    SEvalResult evaluation = EvaluateSession(appInfo, profileSession, startIndex, endIndex);

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

        InstrumentFunctionWithSource(appInfo, evaluation, index - 1, options);
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

SProfileResult ProfileApplicationNoStackTrace(SAppInfo &appInfo, const SProfileOptions &options)
{
  SProfileResult ret;

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
        return ret;
      }

      default:
      {
        UpdateAppInfo(appInfo, debugEvent);
        break;
      }
      }
    }

    const size_t ticks = GetTickCount64();

    if (ticks > lastTicks + 1000)
    {
      ret.indexAtSecond.push_back(ret.directHits.size());
      lastTicks = ticks;
    }

    if (!options.favorPerformance)
      for (auto &_thread : appInfo.threads)
        if (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId)
          SuspendThread(_thread.handle);

    for (auto &_thread : appInfo.threads)
    {
      if (options.favorPerformance && (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId))
        SuspendThread(_thread.handle);

      if (GetThreadContext(_thread.handle, &threadContext))
      {
        if (threadContext.Rip != _thread.lastRip)
        {
          bool external = true;

          for (size_t moduleIndex = 0; moduleIndex < appInfo.modules.size(); moduleIndex++)
          {
            const size_t relativeAddress = threadContext.Rip - appInfo.modules[moduleIndex].moduleBaseAddress;

            if (relativeAddress < appInfo.modules[moduleIndex].endAddress && relativeAddress >= appInfo.modules[moduleIndex].startAddress)
            {
              ret.directHits.emplace_back(relativeAddress, (uint8_t)moduleIndex);
              external = false;
              break;
            }
          }
          
          if (external && options.getStackTraceOnExtern)
          {
            if (options.fastStackTrace)
            {
              constexpr size_t stackDataCount = 64;
              size_t stackData[stackDataCount];

              size_t stackPosition = (threadContext.Rsp & ~(size_t)0x4) - sizeof(stackData) + sizeof(size_t);

              bool found = false;

              while ((stackPosition & 0xFFFFF) > sizeof(stackData) * 2)
              {
                size_t bytesRead = 0;

                if (!ReadProcessMemory(appInfo.processHandle, (void *)stackPosition, stackData, sizeof(stackData), &bytesRead))
                  break;

                for (int64_t i = stackDataCount - 1; i >= 0; i--)
                {
                  for (size_t moduleIndex = 0; moduleIndex < appInfo.modules.size(); moduleIndex++)
                  {
                    if (stackData[i] >= appInfo.modules[moduleIndex].moduleEndAddress)
                      break;

                    const size_t virtualAddress = stackData[i] - appInfo.modules[moduleIndex].moduleBaseAddress;

                    if (virtualAddress >= appInfo.modules[moduleIndex].startAddress)
                    {
                      ret.directHits.emplace_back(virtualAddress, (uint8_t)moduleIndex);
                      found = true;
                      break;
                    }
                  }

                  if (found)
                    break;
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

              while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, appInfo.processHandle, _thread.handle, &stackFrame, &threadContext, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
              {
                for (size_t moduleIndex = 0; moduleIndex < appInfo.modules.size(); moduleIndex++)
                {
                  const size_t stackRelativeAddress = stackFrame.AddrPC.Offset - appInfo.modules[moduleIndex].moduleBaseAddress;

                  if (stackFrame.AddrPC.Segment == 0 && stackRelativeAddress < appInfo.modules[moduleIndex].endAddress && stackRelativeAddress >= appInfo.modules[moduleIndex].startAddress)
                  {
                    ret.directHits.emplace_back(stackRelativeAddress, (uint8_t)moduleIndex);
                    found = true;
                    break;
                  }
                }

                if (found)
                  break;
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

  ret.indexAtSecond.push_back(ret.directHits.size());

  return ret;
}

////////////////////////////////////////////////////////////////////////////////

void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt)
{
  switch (evnt.dwDebugEventCode)
  {
  case CREATE_THREAD_DEBUG_EVENT:
  {
    if (evnt.u.CreateThread.hThread == INVALID_HANDLE_VALUE || evnt.u.CreateThread.hThread == nullptr)
      printf("Invalid Thread Handle for ThreadId %" PRIu32 ".\n", evnt.dwThreadId);
    else
      appInfo.threads.push_back({ evnt.dwThreadId, evnt.u.CreateThread.hThread, 0 });

    break;
  }

  case EXIT_THREAD_DEBUG_EVENT:
  {
    for (size_t i = 0; i < appInfo.threads.size(); i++)
    {
      if (evnt.dwThreadId == appInfo.threads[i].threadId)
      {
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
  {
    wchar_t filename[MAX_PATH];

    SetConsoleColor(CC_DarkGray, CC_Black);

    if (GetModuleFileName((HMODULE)evnt.u.LoadDll.lpBaseOfDll, filename, ARRAYSIZE(filename)))
    {
      if (_VerboseLogging)
        printf("Loaded DLL '%ws'.", filename);

      if (evnt.u.LoadDll.nDebugInfoSize != 0 && evnt.u.LoadDll.dwDebugInfoFileOffset != 0)
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
          IMAGE_DOS_HEADER moduleHeader;
          IMAGE_NT_HEADERS ntHeader;
          size_t bytesRead = 0;

          if (!ReadProcessMemory(appInfo.processHandle, evnt.u.LoadDll.lpBaseOfDll, &moduleHeader, sizeof(moduleHeader), &bytesRead) || bytesRead != sizeof(moduleHeader) || !ReadProcessMemory(appInfo.processHandle, reinterpret_cast<const uint8_t *>(evnt.u.LoadDll.lpBaseOfDll) + moduleHeader.e_lfanew, &ntHeader, sizeof(ntHeader), &bytesRead) || bytesRead != sizeof(ntHeader))
          {
            if (_VerboseLogging)
              puts(" (Failed to load DOS / NT header)");
          }
          else
          {
            CopyString(info.filename, sizeof(info.filename), filename);
            info.moduleName = PathFindFileNameW(info.filename);
            info.moduleBaseAddress = (size_t)evnt.u.LoadDll.lpBaseOfDll;
            info.startAddress = ntHeader.OptionalHeader.BaseOfCode;
            info.endAddress = appInfo.modules[0].startAddress + (size_t)ntHeader.OptionalHeader.SizeOfCode;
            info.moduleEndAddress = appInfo.modules[0].moduleBaseAddress + appInfo.modules[0].endAddress;

            appInfo.modules.push_back(info);

            if (!_VerboseLogging)
              printf("Loaded DLL '%ws'.", filename);

            puts(" (Module Added)");
          }
        }
      }
      else
      {
        if (_VerboseLogging)
          puts(" (Skipped)");
      }
    }
    else
    {
      if (_VerboseLogging)
        printf("Skipping Unknown Module at 0x%" PRIX64 ".\n", (size_t)evnt.u.LoadDll.lpBaseOfDll);
    }

    SetConsoleColor(CC_BrightGray, CC_Black);

    break;
  }

  case UNLOAD_DLL_DEBUG_EVENT:
  {
    wchar_t filename[MAX_PATH];

    SetConsoleColor(CC_DarkGray, CC_Black);

    if (GetModuleFileName((HMODULE)evnt.u.LoadDll.lpBaseOfDll, filename, ARRAYSIZE(filename)))
    {
      if (_VerboseLogging)
        printf("Unloaded DLL '%ws'.", filename);

      bool found = false;

      for (size_t i = 0; i < appInfo.modules.size(); i++)
      {
        if (appInfo.modules[i].moduleBaseAddress == (size_t)evnt.u.UnloadDll.lpBaseOfDll)
        {
          if (!_VerboseLogging)
            printf("Unloaded DLL '%ws'.", filename);

          puts(" (Module Archived)");

          appInfo.inactiveModules.push_back(appInfo.modules[i]);
          appInfo.modules.erase(appInfo.modules.begin() + i);
          break;
        }

        if (!found)
          puts(" (Skipped)");
      }
    }
    else
    {
      if (_VerboseLogging)
        printf("Unloaded Unknown Module at 0x%" PRIX64 ".\n", (size_t)evnt.u.LoadDll.lpBaseOfDll);
    }

    SetConsoleColor(CC_BrightGray, CC_Black);

    break;
  }
  }
}

////////////////////////////////////////////////////////////////////////////////

SEvalResult EvaluateSession(SAppInfo &appInfo, _Inout_ SProfileResult &perfSession, const size_t startIndex, const size_t endIndex)
{
  SEvalResult ret;

  printf("Evaluating %" PRIu64 " selected samples...\n", endIndex - startIndex);

  std::sort(perfSession.directHits.begin() + startIndex, perfSession.directHits.begin() + endIndex);

  if (appInfo.inactiveModules.size() > 0)
    appInfo.modules.insert(appInfo.modules.begin(), std::make_move_iterator(begin(appInfo.inactiveModules)), std::make_move_iterator(end(appInfo.inactiveModules)));

  size_t i = startIndex;

  for (size_t moduleIndex = 0; moduleIndex < appInfo.modules.size(); moduleIndex++)
  {
    CComPtr<IDiaEnumSymbolsByAddr> enumByAddr;
    
    if (FAILED(appInfo.modules[moduleIndex].pdbSession->getSymbolsByAddr(&enumByAddr)))
    {
      printf("Failed to get Iterator for Module '%ws'. Skipping Module.\n", appInfo.modules[moduleIndex].moduleName);
      continue;
    }  

    for (; i < endIndex; i++)
    {
      const SProfileHit hit = perfSession.directHits[i];

      if (hit.GetModule() != (uint8_t)moduleIndex)
        break;

      CComPtr<IDiaSymbol> symbol;

      if (FAILED(enumByAddr->symbolByAddr(1, (DWORD)(hit.GetAddress() - appInfo.modules[moduleIndex].startAddress), &symbol)) || symbol == nullptr)
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
      func.moduleIndex = (uint8_t)hit.GetModule();

      CopyString(func.symbolName, sizeof(func.symbolName), appInfo.modules[func.moduleIndex].moduleName);
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
          break;

        i++;
        func.hitsOffset.emplace_back((uint32_t)(nextHit.GetAddress() - func.symbolStartPos));
      }

      ret.eval.emplace_back(std::move(func));
    }
  }

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

bool LoadBinary(SAppInfo &appInfo, const size_t moduleIndex)
{
  if (appInfo.modules[moduleIndex].pBinary != nullptr)
    return appInfo.modules[moduleIndex].hasDisasm;

  FILE *pFile = _wfopen(appInfo.modules[moduleIndex].filename, L"rb");
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

  appInfo.modules[moduleIndex].pBinary = fileContents;
  appInfo.modules[moduleIndex].binaryLength = fileSize;

  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisDecoderInit(&appInfo.modules[moduleIndex].decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)), "Failed to initialize disassembler.");
  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisFormatterInit(&appInfo.modules[moduleIndex].formatter, ZYDIS_FORMATTER_STYLE_INTEL)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.modules[moduleIndex].formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.modules[moduleIndex].formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)), "Failed to initialize instruction formatter.");

  appInfo.modules[moduleIndex].hasDisasm = true;

  return true;
}

////////////////////////////////////////////////////////////////////////////////

bool InstrumentDisassembly(SAppInfo &appInfo, const SPerfEval &function, const size_t startAddress, const size_t endAddress, const SFuncLineOptions &options, const size_t maxLineHits)
{
  if (startAddress == endAddress)
    return true;

  size_t virtualAddress = startAddress;
  ZydisDecodedInstruction instruction;
  char disasmBuffer[1024] = {};

  const uint8_t *pBinaryAtAddress = appInfo.modules[function.moduleIndex].pBinary;

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
    size_t hits = 0;
    const size_t virtualAddressOffset = virtualAddress - function.symbolStartPos;

    while (hitIndex < function.hitsOffset.size())
    {
      if (function.hitsOffset[hitIndex] > virtualAddressOffset)
        break;
      if (function.hitsOffset[hitIndex] == virtualAddressOffset)
        hits++;

      hitIndex++;
    }

    ERROR_RETURN_IF(!(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&appInfo.modules[function.moduleIndex].decoder, pBinaryAtAddress, endAddress - virtualAddress, &instruction))), "Invalid Instruction at 0x%" PRIX64 ".", virtualAddress);
    ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&appInfo.modules[function.moduleIndex].formatter, &instruction, disasmBuffer, sizeof(disasmBuffer), virtualAddress)), "Failed to Format Instruction at 0x%" PRIX64 ".", virtualAddress);

    SetConsoleColor(hits > expensiveThreshold ? CC_BrightCyan : CC_DarkCyan, CC_Black);

    if (hits > 0)
      printf("0x%08" PRIX64 " | % 5" PRIu64 " | %s\n", virtualAddress, hits, disasmBuffer);
    else
      printf("0x%08" PRIX64 " |       | %s\n", virtualAddress, disasmBuffer);

    virtualAddress += instruction.length;
    pBinaryAtAddress += instruction.length;
  }

  SetConsoleColor(CC_DarkCyan, CC_Black);

  for (size_t i = 0; i < (width - 1); i++)
    putc('-', stdout);

  putc('\n', stdout);

  return true;
}

bool InstrumentFunctionDisassembly(SAppInfo &appInfo, const SPerfEval &function, const SFuncLineOptions &options)
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

  const bool result = InstrumentDisassembly(appInfo, function, function.symbolStartPos, function.symbolEndPos, options, maxHit);
  
  SetConsoleColor(CC_BrightGray, CC_Black);

  return result;
}

////////////////////////////////////////////////////////////////////////////////

bool InstrumentFunctionWithSource(SAppInfo &appInfo, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options)
{
  ERROR_RETURN_IF(evaluation.eval.size() <= index, "Invalid Index.");

  const SPerfEval &function = evaluation.eval[index];
  const bool showDisasm = options.disasmExpensiveLines && LoadBinary(appInfo, function.moduleIndex);

  printf("\nDetails for '%ws':\n\n", function.symbolName);

  SFuncEval lineEval;

  if (!GetDetailedEvaluation(appInfo.modules[function.moduleIndex].pdbSession, function, lineEval) || lineEval.lines.size() == 0)
  {
    puts("Failed to retrieve detailed evaluation.");

    if (showDisasm)
      InstrumentFunctionDisassembly(appInfo, function, options);
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
          InstrumentFunctionDisassembly(appInfo, function, options);
          failedFileDisasmShown = true;
        }

        while (lineEval.lines.size() > 1 && lineEval.lines[i + 1].fileIndex == fileIndex)
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

      // Print Line With Hits.
      {
        printf("# % 8" PRIu64 " | % 5" PRIu64 " | %s\n", currentLine, lineEval.lines[i].hits, fileContents + offset);

        if (showDisasm && lineEval.lines[i].hits > disasmThreshold)
          InstrumentDisassembly(appInfo, function, lineEval.lines[i].startAddress, lineEval.lines[i].endAddress, options, maximumLineHits);

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
            InstrumentDisassembly(appInfo, function, lineEval.lines[i].startAddress, lineEval.lines[i].endAddress, options, maximumLineHits);

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
