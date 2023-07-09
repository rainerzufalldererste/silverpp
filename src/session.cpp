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

////////////////////////////////////////////////////////////////////////////////

struct BinaryReader
{
  uint8_t *pData = nullptr;
  size_t size = 0;
  size_t position = 0;

  inline BinaryReader(uint8_t *pData, const size_t size) : pData(pData), size(size) {};
  inline ~BinaryReader() { free(pData); pData = nullptr; }
};

////////////////////////////////////////////////////////////////////////////////

template <typename T>
bool LoadValue(_Inout_ BinaryReader &reader, _Out_ T *pV, const size_t count = 1)
{
  if (reader.position + sizeof(T) * count > reader.size)
    return false;

  memcpy(pV, reader.pData + reader.position, sizeof(T) * count);

  reader.position += sizeof(T) * count;

  return true;
}

template <typename T>
bool LoadVector(_Inout_ BinaryReader &reader, _Out_ std::vector<T> *pV)
{
  size_t count = 0;

  if (!LoadValue(reader, &count))
    return false;

  for (size_t i = 0; i < count; i++)
  {
    T v;

    if (!LoadValue(reader, &v))
      return false;

    pV->push_back(std::move(v));
  }

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SThreadRip *pRip)
{
  pRip->handle = nullptr;

  if (!LoadValue(reader, &pRip->threadId))
    return false;
  
  if (!LoadValue(reader, &pRip->lastRip))
    return false;

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SModuleInfo *pInfo)
{
  pInfo->hasDisasm = false;
  pInfo->pdbSession = nullptr;

  if (!LoadValue(reader, &pInfo->moduleBaseAddress) || !LoadValue(reader, &pInfo->moduleEndAddress) || !LoadValue(reader, &pInfo->startAddress) || !LoadValue(reader, &pInfo->endAddress) || !LoadValue(reader, pInfo->filename, ARRAYSIZE(pInfo->filename)) || !LoadValue(reader, &pInfo->nameOffset) || !LoadValue(reader, &pInfo->moduleIndex))
    return false;

  CComPtr<IDiaDataSource> pdbSource;

  if (FAILED(CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&pdbSource)) || FAILED(pdbSource->loadDataForExe(pInfo->filename, nullptr, nullptr)) || FAILED(pdbSource->openSession(&pInfo->pdbSession)))
  {
    if (_VerboseLogging)
      printf(" (Failed to load PDB for '%ls')\n", pInfo->filename);
  }

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SNamedLibraryInfo *pInfo)
{
  if (!LoadValue(reader, pInfo->filename, ARRAYSIZE(pInfo->filename)) || !LoadValue(reader, &pInfo->nameOffset) || !LoadValue(reader, &pInfo->moduleBaseAddress) || !LoadValue(reader, &pInfo->moduleEndAddress) || !LoadValue(reader, &pInfo->startAddress) || !LoadValue(reader, &pInfo->endAddress) || !LoadValue(reader, &pInfo->loaded))
    return false;

  if (!LoadVector(reader, &pInfo->functions))
    return false;

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SLibraryFunction *pFunc)
{
  if (!LoadValue(reader, pFunc->name, ARRAYSIZE(pFunc->name)) || !LoadValue(reader, &pFunc->virtualAddressOffset))
    return false;

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SProcessInfo *pProcessInfo)
{
  if (!LoadValue(reader, &pProcessInfo->processId) || !LoadValue(reader, &pProcessInfo->hasName) || !LoadValue(reader, pProcessInfo->name, ARRAYSIZE(pProcessInfo->name)))
    return false;

  if (!LoadVector(reader, &pProcessInfo->threads))
    return false;

  {
    size_t count = 0;

    if (!LoadValue(reader, &count))
      return false;

    for (size_t i = 0; i < count; i++)
    {
      SModuleInfo m;

      if (!LoadValue(reader, &m))
        return false;

      if (i == 0)
      {
        if (wcsncmp(m.filename, pProcessInfo->modules[0].filename, ARRAYSIZE(m.filename)) != 0)
        {
          printf("WARNING: The filename of the loaded session ('%ls') doesn't correspond to the filename launched alongside the executable ('%ls').\n", m.filename, pProcessInfo->modules[0].filename);
        }

        pProcessInfo->modules[0].moduleBaseAddress = m.moduleBaseAddress;
        pProcessInfo->modules[0].moduleEndAddress = m.moduleEndAddress;
        pProcessInfo->modules[0].startAddress = m.startAddress;
        pProcessInfo->modules[0].endAddress = m.endAddress;
      }
      else
      {
        pProcessInfo->modules.push_back(std::move(m));
      }
    }
  }
  
  if (!LoadVector(reader, &pProcessInfo->inactiveModules))
    return false;

  if (!LoadVector(reader, &pProcessInfo->foreignModules))
    return false;

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SProfileHit *pResult)
{
  if (!LoadValue(reader, &pResult->packed))
    false;

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SProfileIndirectHit *pResult)
{
  if (!LoadValue(reader, &pResult->packed) || !LoadValue(reader, &pResult->packed))
    return false;

  return true;
}

bool LoadValue(_Inout_ BinaryReader &reader, SProcessProfileResult *pResult)
{
  if (!LoadValue(reader, &pResult->processId))
    return false;
  
  if (!LoadVector(reader, &pResult->directHits))
    return false;

  if (!LoadVector(reader, &pResult->directHitIndexAtSecond))
    return false;

  if (!LoadVector(reader, &pResult->indirectHits))
    return false;

  if (!LoadVector(reader, &pResult->indirectHitIndexAtSecond))
    return false;

  return true;
}

////////////////////////////////////////////////////////////////////////////////

struct BinaryWriter
{
  uint8_t *pData = nullptr;
  size_t size = 0;
  size_t capacity = 0;

  inline ~BinaryWriter() { if (pData) free(pData); pData = nullptr; capacity = 0; size = 0; }

  inline bool reserve(const size_t bytes)
  {
    if (capacity >= size + bytes)
      return true;

    const size_t newCapacity = (max(size + bytes * 2, size * 2 + 1) + 1023) & ~(size_t)1023;

    pData = reinterpret_cast<uint8_t *>(realloc(pData, newCapacity));

    if (pData == nullptr)
      return false;

    capacity = newCapacity;

    return true;
  }
};

////////////////////////////////////////////////////////////////////////////////

template <typename T>
bool StoreValue(_Inout_ BinaryWriter &writer, const T &v)
{
  writer.reserve(sizeof(T));
  memcpy(writer.pData + writer.size, &v, sizeof(T));
  writer.size += sizeof(T);

  return true;
}

template <typename T>
bool StoreValue(_Inout_ BinaryWriter &writer, const T *pV, const size_t count)
{
  writer.reserve(sizeof(T) * count);
  memcpy(writer.pData + writer.size, pV, sizeof(T) * count);
  writer.size += sizeof(T) * count;

  return true;
}

template <typename T>
bool StoreVector(_Inout_ BinaryWriter &writer, const std::vector<T> &v)
{
  StoreValue(writer, v.size());
  
  for (size_t i = 0; i < v.size(); i++)
    if (!StoreValue(writer, v[i]))
      return false;

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SThreadRip &rip)
{
  StoreValue(writer, rip.threadId);
  StoreValue(writer, rip.lastRip);

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SModuleInfo &info)
{
  StoreValue(writer, info.moduleBaseAddress);
  StoreValue(writer, info.moduleEndAddress);
  StoreValue(writer, info.startAddress);
  StoreValue(writer, info.endAddress);
  StoreValue(writer, info.filename, ARRAYSIZE(info.filename));
  StoreValue(writer, info.nameOffset);
  StoreValue(writer, info.moduleIndex);

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SNamedLibraryInfo &info)
{
  StoreValue(writer, info.filename, ARRAYSIZE(info.filename));
  StoreValue(writer, info.nameOffset);
  StoreValue(writer, info.moduleBaseAddress);
  StoreValue(writer, info.moduleEndAddress);
  StoreValue(writer, info.startAddress);
  StoreValue(writer, info.endAddress);
  StoreValue(writer, info.loaded);

  if (!StoreVector(writer,  info.functions))
    return false;

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SLibraryFunction &func)
{
  StoreValue(writer, func.name, ARRAYSIZE(func.name));
  StoreValue(writer, func.virtualAddressOffset);

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SProcessInfo &processInfo)
{
  StoreValue(writer, processInfo.processId);
  StoreValue(writer, processInfo.hasName);
  StoreValue(writer, processInfo.name, ARRAYSIZE(processInfo.name));
  
  if (!StoreVector(writer,  processInfo.threads))
    return false;
  
  if (!StoreVector(writer,  processInfo.modules))
    return false;
  
  if (!StoreVector(writer,  processInfo.inactiveModules))
    return false;
  
  if (!StoreVector(writer,  processInfo.foreignModules))
    return false;

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SProfileHit &result)
{
  StoreValue(writer, result.packed);

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SProfileIndirectHit &result)
{
  StoreValue(writer, result.packed);
  StoreValue(writer, result.packed);

  return true;
}

bool StoreValue(_Inout_ BinaryWriter &writer, const SProcessProfileResult &result)
{
  StoreValue(writer, result.processId);
  StoreVector(writer,  result.directHits);
  StoreVector(writer,  result.directHitIndexAtSecond);
  StoreVector(writer,  result.indirectHits);
  StoreVector(writer,  result.indirectHitIndexAtSecond);

  return true;
}

////////////////////////////////////////////////////////////////////////////////

constexpr uint32_t FormatVersion = 1;

bool StoreSession(const wchar_t *filename, const SAppInfo &appInfo, _In_ const SProfileResult &result)
{
  BinaryWriter writer;
  StoreValue(writer, FormatVersion);

  if (!StoreValue(writer, appInfo.procs[0]))
    return false;

  if (!StoreValue(writer, result.procs[0]))
    return false;

  FILE *pFile = _wfopen(filename, L"wb");
  
  if (pFile == nullptr)
    return false;

  if (writer.size != fwrite(writer.pData, 1, writer.size, pFile))
  {
    fclose(pFile);
    return false;
  }

  fclose(pFile);

  return true;
}

bool LoadSession(const wchar_t *filename, _Out_ SAppInfo *pAppInfo, _Out_ SProfileResult *pResult)
{
  FILE *pFile = _wfopen(filename, L"rb");

  if (pFile == nullptr)
    return false;

  fseek(pFile, 0, SEEK_END);
  const size_t fileSize = _ftelli64(pFile);

  if (fileSize == 0)
    return false;

  fseek(pFile, 0, SEEK_SET);

  uint8_t *pData = reinterpret_cast<uint8_t *>(malloc(fileSize));

  if (pData == nullptr)
  {
    fclose(pFile);
    return false;
  }

  BinaryReader reader(pData, fileSize); // will free `pData` on scope end.
  pData = nullptr;

  if (reader.size != fread(reader.pData, 1, reader.size, pFile))
  {
    fclose(pFile);
    return false;
  }

  fclose(pFile);

  uint32_t formatVersion;

  if (!LoadValue(reader, &formatVersion) || formatVersion != FormatVersion)
    return false;

  pAppInfo->procs_size = 1;
  pAppInfo->runningProcesses = 0;

  if (!LoadValue(reader, &pAppInfo->procs[0]))
    return false;

  pResult->procs_size = 1;

  if (!LoadValue(reader, &pResult->procs[0]))
    return false;

  return true;
}
