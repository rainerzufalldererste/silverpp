#include "silverpp.h"

bool _VerboseLogging = false;

static HANDLE _StdOutHandle = nullptr;

size_t GetConsoleWidth()
{
  if (_StdOutHandle == nullptr)
    _StdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

  CONSOLE_SCREEN_BUFFER_INFO bufferInfo;
  GetConsoleScreenBufferInfo(_StdOutHandle, &bufferInfo);

  return bufferInfo.srWindow.Right - bufferInfo.srWindow.Left + 1;
}

void SetConsoleColor(const ConsoleColor foreground, const ConsoleColor background)
{
  if (_StdOutHandle == nullptr)
    _StdOutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

  const WORD fgColour = (foreground & 0xF);
  const WORD bgColour = (background & 0xF);

  if (_StdOutHandle != nullptr && _StdOutHandle != INVALID_HANDLE_VALUE)
    SetConsoleTextAttribute(_StdOutHandle, fgColour | (bgColour << 4));
}
