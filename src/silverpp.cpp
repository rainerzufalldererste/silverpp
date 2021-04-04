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
  size_t symbolStartPos;
  DWORD sector, offset;

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
  wchar_t sourceFile[MAX_PATH] = {};
  uint8_t *pBinary = nullptr;
  size_t binaryLength = 0;

  bool hasDisasm = false;

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

  inline bool operator < (const SLineEval &other)
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
  wchar_t filename[256];
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

SProfileResult ProfileApplication(SAppInfo &appInfo);
void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt);
SEvalResult EvaluateSession(_In_ CComPtr<IDiaSession> &session, _Inout_ SProfileResult &perfSession);
bool GetDetailedEvaluation(_In_ CComPtr<IDiaSession> &session, _In_ const SPerfEval &function, _Inout_ SFuncEval &funcEval);
bool InstrumentFunctionWithSource(CComPtr<IDiaSession> &pdbSession, SAppInfo &appInfo, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options);
bool LoadBinary(SAppInfo &appInfo);
bool InstrumentDisassembly(SAppInfo &appInfo, const SPerfEval &function, const size_t virtualStartAddress, const size_t virtualEndAddress, const SFuncLineOptions &options, const size_t maxLineHits);

////////////////////////////////////////////////////////////////////////////////

inline void CopyString(wchar_t *dst, const size_t dstSize, const wchar_t *src)
{
  const size_t textLength = min(dstSize - sizeof(wchar_t), wcslen(src) * sizeof(wchar_t));
  memcpy(dst, src, textLength);
  dst[textLength / sizeof(wchar_t)] = '\0';
}

////////////////////////////////////////////////////////////////////////////////

int32_t main(void)
{
  int32_t argc = 0;
  wchar_t **pArgv = CommandLineToArgvW(GetCommandLineW(), &argc);
  FATAL_IF(argc == 1, "Usage: silverpp <ExecutablePath> <Args>");

  wchar_t workingDirectory[MAX_PATH];
  FATAL_IF(0 == GetCurrentDirectory(ARRAYSIZE(workingDirectory), workingDirectory), "Failed to retrieve working directory. Aborting.");

  wchar_t *appPath = pArgv[1];
  wchar_t *pdbPath = nullptr;

  CComPtr<IDiaSession> pdbSession;

  // Attempt to read PDB.
  {
    CComPtr<IDiaDataSource> pdbSource;

    FATAL_IF(FAILED(CoInitialize(nullptr)), "Failed to Initialize. Aborting.");

    FATAL_IF(FAILED(CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&pdbSource)), "Failed to retrieve an instance of the PDB Parser.");

    if (pdbPath == nullptr || FAILED(pdbSource->loadDataFromPdb(pdbPath)))
      if (FAILED(pdbSource->loadDataForExe(appPath, nullptr, nullptr)))
        FATAL("Failed to find pdb for the specified path.");

    FATAL_IF(FAILED(pdbSource->openSession(&pdbSession)), "Failed to Open Session.");
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
  CopyString(appInfo.modules.sourceFile, sizeof(appInfo.modules.sourceFile), appPath);
  
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

  SEvalResult evaluation = EvaluateSession(pdbSession, profileSession);

  puts("Sorting Evaluation...");

  std::sort(evaluation.eval.begin(), evaluation.eval.end());

  puts("\nResults:\n");

  size_t count = 0;

  for (const auto &_func : evaluation.eval)
  {
    ++count;

    if (count > 50)
      break;

    printf("#%02" PRIu64 " | % 6" PRIu64 " %ws\n", count, _func.hitsOffset.size(), _func.symbolName);
  }

  // Explore Stackless Performance Evaluation.
  {
    SFuncLineOptions options;

    // Select a function to profile and display hits in the source file.
    while (true)
    {
      puts("\n\nIndex (or 0 to exit)?");

      size_t index;

      if (1 != scanf("%" PRIu64 "", &index))
        continue;

      if (index == 0)
        break;

      InstrumentFunctionWithSource(pdbSession, appInfo, evaluation, index - 1, options);
    }
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
  DWORD virtualAddress;
  DWORD tag;

  if (symbol->get_relativeVirtualAddress(&virtualAddress) != S_OK)
    virtualAddress = 0;
  
  if (SUCCEEDED(symbol->get_symTag(&tag)) && tag == SymTagFunction)
  {
    wchar_t *symbolName = nullptr;
  
    if (FAILED(symbol->get_name(&symbolName)))
    {
      if (symbolName != nullptr)
        SysFreeString(symbolName);
    }
    else
    {
      SPerfEval func;
      func.symbolStartPos = virtualAddress;

      CopyString(func.symbolName, sizeof(func.symbolName), symbolName);
      SysFreeString(symbolName);
      
      size_t length;

      if (FAILED(symbol->get_length(&length)))
        return virtualAddress;

      const size_t endAddress = virtualAddress + length;

      while (positions.size() > 0 && positions[0] < virtualAddress) // Discard hits before this function. We're iterating linearly from front to back.
        positions.pop_front(); // Let's hope this doesn't happen too much...

      while (positions.size() > 0 && positions[0] >= virtualAddress && positions[0] < endAddress)
      {
        func.hitsOffset.emplace_back((uint32_t)(positions.front() - virtualAddress));
        positions.pop_front();
      }

      if (func.hitsOffset.size() > 0)
      {
        if (FAILED(symbol->get_addressSection(&func.sector)))
          func.sector = (DWORD)-1;

        if (FAILED(symbol->get_addressOffset(&func.offset)))
          func.offset = (DWORD)-1;

        evaluation.emplace_back(std::move(func));
      }
    }
  }

  return virtualAddress;
}

SEvalResult EvaluateSession(_In_ CComPtr<IDiaSession> &session, _Inout_ SProfileResult &perfSession)
{
  SEvalResult ret;

  std::sort(perfSession.directHits.begin(), perfSession.directHits.end());

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

bool LoadBinary(SAppInfo &appInfo)
{
  if (appInfo.modules.pBinary != nullptr)
    return appInfo.modules.hasDisasm;

  FILE *pFile = _wfopen(appInfo.modules.sourceFile, L"rb");
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

  appInfo.modules.pBinary = fileContents;
  appInfo.modules.binaryLength = fileSize;

  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisDecoderInit(&appInfo.modules.decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64)), "Failed to initialize disassembler.");
  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisFormatterInit(&appInfo.modules.formatter, ZYDIS_FORMATTER_STYLE_INTEL)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.modules.formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.modules.formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)), "Failed to initialize instruction formatter.");

  appInfo.modules.hasDisasm = true;

  return true;
}

////////////////////////////////////////////////////////////////////////////////

bool InstrumentDisassembly(SAppInfo &appInfo, const SPerfEval &function, const size_t startAddress, const size_t endAddress, const SFuncLineOptions &options, const size_t maxLineHits)
{
  size_t virtualAddress = startAddress;
  ZydisDecodedInstruction instruction;
  char disasmBuffer[1024] = {};

  const uint8_t *pBinaryAtAddress = appInfo.modules.pBinary;

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

    SetConsoleColor(hits > expensiveThreshold ? CC_BrightCyan : CC_DarkCyan, CC_Black);

    ERROR_RETURN_IF(!(ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&appInfo.modules.decoder, pBinaryAtAddress, endAddress - virtualAddress, &instruction))), "Invalid Instruction at 0x%" PRIX64 ".", virtualAddress);
    ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&appInfo.modules.formatter, &instruction, disasmBuffer, sizeof(disasmBuffer), virtualAddress)), "Failed to Format Instruction at 0x%" PRIX64 ".", virtualAddress);

    printf("       % 5" PRIu64 " | %s\n", hits, disasmBuffer);

    virtualAddress += instruction.length;
    pBinaryAtAddress += instruction.length;
  }

  SetConsoleColor(CC_DarkCyan, CC_Black);

  for (size_t i = 0; i < (width - 1); i++)
    putc('-', stdout);

  putc('\n', stdout);

  return true;
}

////////////////////////////////////////////////////////////////////////////////

bool InstrumentFunctionWithSource(CComPtr<IDiaSession> &pdbSession, SAppInfo &appInfo, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options)
{
  ERROR_RETURN_IF(evaluation.eval.size() <= index, "Invalid Index.");

  const SPerfEval &function = evaluation.eval[index];
  const bool showDisasm = options.disasmExpensiveLines && LoadBinary(appInfo);

  printf("\nDetails for '%ws':\n\n", function.symbolName);

  SFuncEval lineEval;

  if (!GetDetailedEvaluation(pdbSession, function, lineEval) || lineEval.lines.size() == 0)
  {
    puts("Failed to retrieve detailed evaluation.");
  }
  else
  {
    size_t maximumLineHits = 0;

    for (const auto &_line : lineEval.lines)
      if (_line.hits > maximumLineHits)
        maximumLineHits = _line.hits;

    const size_t expensiveThreshold = (size_t)(maximumLineHits * options.expensiveLineThreshold);
    const size_t relevantThreshold = (size_t)(maximumLineHits * options.relevantLineThreshold);
    const size_t disasmThreshold = (size_t)(maximumLineHits * options.disasmLineThreshold);

    for (size_t i = 0; i < lineEval.lines.size(); i++)
    {
      const size_t fileIndex = lineEval.lines[i].fileIndex;
      constexpr size_t extraLines = 5;
      size_t targetLine = max(1, (lineEval.lines[i].line, lineEval.lines[i].line - extraLines)); // To prevent buffer overflows.

      FILE *pFile = _wfopen(lineEval.files[fileIndex].filename, L"rb");

      if (pFile == nullptr)
      {
        printf("Failed to read file '%ws'.\n", lineEval.files[fileIndex].filename);

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
        printf("#% 5" PRIu64 "       | %s\n", currentLine, fileContents + offset);

        offset += strlen(fileContents + offset) + 1;
        currentLine++;
      }

      ERROR_CONTINUE_IF(offset >= fileSize, "Unexpected End Of File.");

      SetConsoleColor(lineEval.lines[i].hits > expensiveThreshold ? CC_BrightRed : (lineEval.lines[i].hits > relevantThreshold ? CC_BrightYellow : CC_BrightGray), CC_Black);

      // Print Line With Hits.
      {
        printf("#% 5" PRIu64 " % 5" PRIu64 " | %s\n", currentLine, lineEval.lines[i].hits, fileContents + offset);

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
          printf("#% 5" PRIu64 "       | %s\n", currentLine, fileContents + offset);

          offset += strlen(fileContents + offset) + 1;
          currentLine++;
        }

        ERROR_CONTINUE_IF(offset >= fileSize, "Unexpected End Of File.");

        SetConsoleColor(lineEval.lines[i].hits > expensiveThreshold ? CC_BrightRed : (lineEval.lines[i].hits > relevantThreshold ? CC_BrightYellow : CC_BrightGray), CC_Black);

        // Print Line With Hits.
        {
          printf("#% 5" PRIu64 " % 5" PRIu64 " | %s\n", currentLine, lineEval.lines[i].hits, fileContents + offset);

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
        printf("#% 5" PRIu64 "       | %s\n", currentLine, fileContents + offset);

        offset += strlen(fileContents + offset) + 1;
        currentLine++;
      }

      SetConsoleColor(CC_BrightGray, CC_Black);
    }
  }

  return true;
}
