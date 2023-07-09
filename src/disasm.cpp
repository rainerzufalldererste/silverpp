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
      if (function.hitsOffset[hitIndex] > virtualAddressOffset + instruction.length - 1)
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
