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
            if (options.favorPerformance && (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId))
              SuspendThread(_thread.handle);

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

            if (options.favorPerformance && (!hasDebugEvent || debugEvent.dwThreadId != _thread.threadId))
              ResumeThread(_thread.handle);
          }

          _thread.lastRip = threadContext.Rip;
        }
      }
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
