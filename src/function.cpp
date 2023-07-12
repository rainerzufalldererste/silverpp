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

bool LoadBinary(SAppInfo &appInfo, const size_t processIndex, const size_t moduleIndex);

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

bool InstrumentFunctionWithSource(SAppInfo &appInfo, const size_t processIndex, const SEvalResult &evaluation, const size_t index, const SFuncLineOptions &options)
{
  ERROR_RETURN_IF(evaluation.eval.size() <= index, "Invalid Index.");

  const SPerfEval &function = evaluation.eval[index];
  const bool showDisasm = options.disasmExpensiveLines && LoadBinary(appInfo, processIndex, function.moduleIndex);

  printf("\nDetails for '%ws':\n\n", function.symbolName);

  SFuncEval lineEval;

  if (!EvaluateFunction(appInfo.procs[processIndex].modules[function.moduleIndex].pdbSession, function, lineEval) || lineEval.lines.size() == 0)
  {
    puts("Failed to retrieve detailed evaluation.");

    if (showDisasm)
      InstrumentFunctionDisassembly(appInfo, processIndex, function, options);
  }
  else // load file, print relevant lines.
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

////////////////////////////////////////////////////////////////////////////////

bool EvaluateFunction(_In_ CComPtr<IDiaSession> &session, _In_ const SPerfEval &function, _Inout_ SFuncEval &funcEval)
{
  funcEval.files.clear();
  funcEval.lines.clear();

  ERROR_RETURN_IF(function.sector == (DWORD)-1 || function.offset == (DWORD)-1, "Unknown Sector or Offset for this Function.");

  for (size_t i = 0; i < function.hitsOffset.size(); i++)
  {
    CComPtr<IDiaEnumLineNumbers> lineNumEnum;

    const size_t hit = function.hitsOffset[i];

    if (FAILED(session->findLinesByAddr(function.sector, function.offset + hit, 1, &lineNumEnum)))
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

    if (FAILED(lineNumber->get_virtualAddress(&address)) || address > hit + function.symbolStartPos) // if we can't get a length or the retrieved end would be out of bounds.
      address = hit;

    DWORD length;

    if (FAILED(lineNumber->get_length(&length)))
      length = (DWORD)(hit + function.symbolStartPos - address);

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

  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisDecoderInit(&appInfo.procs[processIndex].modules[moduleIndex].decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)), "Failed to initialize disassembler.");
  ERROR_RETURN_IF(!ZYAN_SUCCESS(ZydisFormatterInit(&appInfo.procs[processIndex].modules[moduleIndex].formatter, ZYDIS_FORMATTER_STYLE_INTEL)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.procs[processIndex].modules[moduleIndex].formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) || !ZYAN_SUCCESS(ZydisFormatterSetProperty(&appInfo.procs[processIndex].modules[moduleIndex].formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)), "Failed to initialize instruction formatter.");

  appInfo.procs[processIndex].modules[moduleIndex].hasDisasm = true;

  return true;
}
