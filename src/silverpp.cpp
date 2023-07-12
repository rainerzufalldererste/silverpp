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

#include "silverpp.h"

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

#define CMD_PARAM_STORE_SESSION "--store"
wchar_t _CMD_PARAM_STORE_SESSION[] = TEXT(CMD_PARAM_STORE_SESSION);

#define CMD_PARAM_LOAD_SESSION "--load"
wchar_t _CMD_PARAM_LOAD_SESSION[] = TEXT(CMD_PARAM_LOAD_SESSION);

////////////////////////////////////////////////////////////////////////////////

int32_t main(void)
{
  wchar_t *commandLine = GetCommandLineW();

  int32_t argc = 0;
  wchar_t **pArgv = CommandLineToArgvW(commandLine, &argc);
  FATAL_IF(argc == 1, "\nUsage: silverpp <ExecutablePath>\n\n Optional Parameters:\n\n\t" CMD_PARAM_INDIRECT_HITS "\t\t | Trace external Samples back to the calling Function\n\t" CMD_PARAM_STACK_TRACE "\t\t\t | Capture Stack Traces for all Samples\n\t" CMD_PARAM_FAST_STACK_TRACE "\t\t | Fast (but possibly less accurate) Stack Traces\n\t" CMD_PARAM_FAVOR_ACCURACY "\t | Favor Sampling Accuracy over Application Performance\n\t" CMD_PARAM_ANALYZE_DELAYS "\t | Capture sample even if stuck on the same instruction (may cause accidental multiple hits)\n\t" CMD_PARAM_SAMPLING_DELAY " <milliseconds>\t | Additional Sampling Delay (Improves performance at the cost of Samples)\n\t" CMD_PARAM_NO_DISASM "\t\t | Don't display disassembly for expensive lines\n\t" CMD_PARAM_VERBOSE "\t\t | Enable verbose logging\n\t" CMD_PARAM_STORE_SESSION " <File>\t | Store the captured state in a file.\n\t" CMD_PARAM_LOAD_SESSION " <File>\t | Load a captured state from file.\n\t" CMD_PARAM_ARGS_PASS_THROUGH " <Args>\t\t | Pass the remaining Arguments to the Application being profiled\n");

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
  const wchar_t *storeSessionName = nullptr;
  const wchar_t *loadSessionName = nullptr;
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
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_STORE_SESSION) == 0 && argsRemaining > 1)
    {
      storeSessionName = pArgv[argIndex + 1];

      argsRemaining -= 2;
      argIndex += 2;
    }
    else if (wcscmp(pArgv[argIndex], _CMD_PARAM_LOAD_SESSION) == 0 && argsRemaining > 1)
    {
      loadSessionName = pArgv[argIndex + 1];

      argsRemaining -= 2;
      argIndex += 2;
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
  if (!loadSessionName)
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
  if (!loadSessionName)
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
  if (!loadSessionName)
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

    SProfileResult profileSession;
    size_t profileSessionIndex = 0;

    if (!loadSessionName)
    {
      profileSession = std::move(ProfileApplicationNoStackTrace(appInfo, profileOptions));

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

      if (storeSessionName != nullptr)
        if (!StoreSession(storeSessionName, appInfo, profileSession))
          printf("Failed to store session in '%ls'.\n", storeSessionName);
    }
    else
    {
      FATAL_IF(!LoadSession(loadSessionName, &appInfo, &profileSession), "Failed to load profile session from '%ls'. Aborting.", loadSessionName);
    }
    
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
