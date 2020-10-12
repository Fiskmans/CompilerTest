#pragma once
#include <vector>
#include <string>


void MakeConsoleGreen();
void ResetConsole();
void MakeConsoleRed();

void DumpToFile(const std::vector<char>& aData, const std::string& aFilePath);
void BinaryDump(const char* data, size_t size, size_t rowSize = 16);