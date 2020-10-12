#include "ConsoleHelpers.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <Windows.h>


void MakeConsoleGreen()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
}

void ResetConsole()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void MakeConsoleRed()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
}


void DumpToFile(const std::vector<char>& aData, const std::string& aFilePath)
{
	std::ofstream file;
	file.open(aFilePath);
	if (file)
	{
		std::cout << "Dumping data to: [" << aFilePath << "]" << std::endl;

		for (unsigned char c : aData)
		{
			file << "\\x" << std::hex << int(c);
		}
	}
	else
	{
		std::cout << "Could not open [" << aFilePath << "] for writing" << std::endl;
	}
}

void BinaryDump(const char* data, size_t size, size_t rowSize)
{

	for (size_t row = 0; row < size; row += 16)
	{
		std::cout << "\t";
		for (size_t byteindex = row; byteindex < size && byteindex - row < rowSize; byteindex++)
		{
			unsigned char currentbyte = data[byteindex];
			if ((currentbyte <= 'Z' && currentbyte >= 'A') || (currentbyte <= 'z' && currentbyte >= 'a'))
			{
				std::cout << char(currentbyte) << "  ";
			}
			else if (currentbyte == '\n')
			{
				std::cout << "\\n ";
			}
			else if (currentbyte == 0)
			{
				std::cout << "__ ";
			}
			else
			{
				unsigned char low = currentbyte & 0x0F;
				unsigned char high = (currentbyte & 0xF0) >> 4;

				std::cout << char((high > 9 ? 'A' + high - 10 : '0' + high));
				std::cout << char((low > 9 ? 'A' + low - 10 : '0' + low));
				std::cout << ' ';
			}
		}
		std::cout << std::endl;
	}
}
