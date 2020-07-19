
#include <iostream>
#include <string>
#include <fstream>
#include <Windows.h>


void Decompile(const std::string& aFilePath)
{
	std::cout << "Decompiling: " + aFilePath << std::endl;

	std::ifstream inputFile;
	inputFile.open(aFilePath, std::ios::binary | std::ios::in);

	if (inputFile)
	{
		IMAGE_DOS_HEADER dosheader;
		inputFile.read(reinterpret_cast<char*>(&dosheader), sizeof(dosheader));
		std::cout << "Dos compatability header [0x" << std::hex << sizeof(IMAGE_DOS_HEADER) << "]:" << std::endl;


		std::cout << "\tMagic number:\t\t\t0x" << std::hex << dosheader.e_magic << "\t" << std::string(reinterpret_cast<char*>(&dosheader.e_magic),sizeof(dosheader.e_magic)) << std::endl;
		std::cout << "\tBytes on last page:\t\t" << dosheader.e_cblp << std::endl;
		std::cout << "\tPages in file:\t\t\t" << dosheader.e_cp << std::endl;
		std::cout << "\tRelocations:\t\t\t" << dosheader.e_crlc << std::endl;
		std::cout << "\tHeader size (paragraphs):\t" << dosheader.e_cparhdr << std::endl;
		std::cout << "\tMinimum extra paragraphs:\t" << dosheader.e_minalloc << std::endl;
		std::cout << "\tMaximum extra paragraphs:\t" << dosheader.e_maxalloc << std::endl;
		std::cout << "\tSS value:\t\t\t0x" << dosheader.e_ss << std::endl;
		std::cout << "\tSP value:\t\t\t0x" << dosheader.e_sp << std::endl;
		std::cout << "\tChecksum:\t\t\t0x" << std::hex << dosheader.e_csum << std::endl;
		std::cout << "\tIP value:\t\t\t" << dosheader.e_ip << std::endl;
		std::cout << "\tCS value:\t\t\t" << dosheader.e_cs << std::endl;
		std::cout << "\tAddress of relocation:\t\t0x" << std::hex << dosheader.e_lfarlc << std::endl;
		std::cout << "\tOverlay number:\t\t\t" << dosheader.e_ovno << std::endl;
		for (size_t i = 0; i < 4; i++)
		{
			std::cout << "\tReserved " + std::to_string(i) + ":\t\t\t" << dosheader.e_res[i] << std::endl;
		}
		std::cout << "\tOEM id:\t\t\t\t" << dosheader.e_oemid << std::endl;
		std::cout << "\tOEM info:\t\t\t" << dosheader.e_oeminfo << std::endl;
		for (size_t i = 0; i < 10; i++)
		{
			std::cout << "\tReserved second " + std::to_string(i) + ":\t\t" << dosheader.e_res2[i] << std::endl;
		}
		std::cout << "\tNew Pe header location:\t\t0x" << std::hex << dosheader.e_lfanew << std::endl;
	}
	else
	{
		std::cout << "Could not open file" << std::endl;
	}
}

int main(int argc, char** argv)
{
	for (size_t i = 0; i < argc; i++)
	{
		Decompile(argv[i]);
		if (i + 1 < argc)
		{
			system("pause");
		}
	}

    std::cout << "No more files to decompile\n";
	system("pause");
}
