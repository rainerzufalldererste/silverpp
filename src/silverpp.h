////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2021-2023, Christoph Stiller. All rights reserved.
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

#ifndef silverpp_h__
#define silverpp_h__

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
#define ZYDIS_STATIC_BUILD
#include "Zydis.h"
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

inline bool CompareHits(const SLineEval &a, const SLineEval &b)
{
  return a.hits > b.hits;
}

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

////////////////////////////////////////////////////////////////////////////////

struct SFuncLineOptions
{
  bool decompileExpensiveLines = true;
  bool disasmExpensiveLines = true;
  float expensiveLineThreshold = 0.5;
  float relevantLineThreshold = 0.1;
  float disasmLineThreshold = 0.3;
  float expensiveAsmThreshold = 0.1;
  size_t minAsmSamples = 8;
};

////////////////////////////////////////////////////////////////////////////////

extern bool _VerboseLogging;

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

void SetConsoleColor(const ConsoleColor foreground, const ConsoleColor background);
size_t GetConsoleWidth();

////////////////////////////////////////////////////////////////////////////////

inline void CopyString(wchar_t *dst, const size_t dstBytes, const wchar_t *src)
{
  wcsncpy(dst, src, dstBytes / sizeof(wchar_t));
}

inline void CopyString(char *dst, const size_t dstBytes, const char *src)
{
  strncpy(dst, src, dstBytes);
}

////////////////////////////////////////////////////////////////////////////////

bool GetPdbSource(_Out_ IDiaDataSource **ppPdbSource, const wchar_t *pdbPath, const wchar_t *appPath, SProcessInfo &procInfo);
SProfileResult ProfileApplicationNoStackTrace(SAppInfo &appInfo, const SProfileOptions &options);
void UpdateAppInfo(SAppInfo &appInfo, const DEBUG_EVENT &evnt);
SEvalResult EvaluateSession(SAppInfo &appInfo, _Inout_ SProcessProfileResult &perfSession, const size_t startIndex, const size_t endIndex, const size_t indirectStartIndex, const size_t indirectEndIndex);

bool StoreSession(const wchar_t *filename, const SAppInfo &appInfo, _In_ const SProfileResult &result);
bool LoadSession(const wchar_t *filename, _Out_ SAppInfo *pAppInfo, _Out_ SProfileResult *pResult);

// Returns the next start index, when displaying incrementally.
size_t DisplayOffsetIndirectHits(SAppInfo &appInfo, const size_t processIndex, const SPerfEval &function, const size_t startOffset, const size_t endOffset, const size_t indirectHitsStartIndex);

bool EvaluateFunction(_In_ CComPtr<IDiaSession> &session, _In_ const SPerfEval &function, _Inout_ SFuncEval &funcEval);
bool InstrumentFunctionWithSource(SAppInfo &appInfo, const size_t processIndex, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options);

bool InstrumentDisassembly(SAppInfo &appInfo, const size_t processIndex, const SPerfEval &function, const size_t startAddress, const size_t endAddress, const SFuncLineOptions &options, const size_t maxLineHits, size_t *pIndirectHitsStartIndex);
bool InstrumentFunctionDisassembly(SAppInfo &appInfo, const size_t processIndex, const SPerfEval &function, const SFuncLineOptions &options);

#endif // silverpp_h__
