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
