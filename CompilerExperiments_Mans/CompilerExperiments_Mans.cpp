#include <iostream>

#include <fstream>
#include <sstream>
#include <Windows.h>
#include <time.h>


// http://www.csn.ul.ie/~caolan/pub/winresdump/winresdump/doc/pefile2.html

// https://www.amd.com/system/files/TechDocs/24594.pdf

 // https://www.mitec.cz/exe.html

#define WIPE(arg) memset(&arg,0,sizeof(arg));


#pragma pack(push,1)
struct FiskExeHeader
{
	IMAGE_DOS_HEADER mzHeader;
	unsigned int signature;
	IMAGE_FILE_HEADER peFileHeader;
	IMAGE_OPTIONAL_HEADER64 peOptionalHeader;
};
#pragma pack(pop)

size_t CeilToSmallestMultiple(size_t aSize, size_t aMultiple)
{
	if (aSize % aMultiple == 0)
	{
		return aSize; //already perfect, just like you
	}

	return (aSize / aMultiple + 1) * aMultiple;
}

namespace ByteSuffixes
{
	size_t operator"" b(unsigned long long aArgument)
	{
		return aArgument;
	}

	size_t operator"" kb(unsigned long long aArgument)
	{
		return aArgument << 10;
	}

	size_t operator"" mb(unsigned long long aArgument)
	{
		return aArgument << 20;
	}

	size_t operator"" gb(unsigned long long aArgument)
	{
		return aArgument << 30;
	}
}

void ExportMachineCode(const char* aCode, size_t aCodeSize, const std::string aFilename)
{
	WORD sectionCount = 0;

	using namespace ByteSuffixes;

	WORD stackSize = 64kb;
	WORD stackCommitedSize = 4kb;
	WORD heapSize = 4gb;
	WORD heapSizeCommited = 4mb;


	FiskExeHeader header;
	{	//DOS Compatability header

		WIPE(header.mzHeader);

		header.mzHeader.e_magic = IMAGE_DOS_SIGNATURE;
		header.mzHeader.e_lfanew = offsetof(FiskExeHeader, signature);

		header.signature = IMAGE_NT_SIGNATURE;
	}

	{ // PE Header
		WIPE(header.peFileHeader);

		header.peFileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
		header.peFileHeader.NumberOfSections = sectionCount;
		time(reinterpret_cast<time_t*>(header.peFileHeader.TimeDateStamp));
		header.peFileHeader.PointerToSymbolTable = NULL;
		header.peFileHeader.NumberOfSymbols = 0;
		header.peFileHeader.SizeOfOptionalHeader = sizeof(header.peOptionalHeader);
		header.peFileHeader.Characteristics = IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP | IMAGE_FILE_NET_RUN_FROM_SWAP;
	}

	{ // PE Optional header
		WIPE(header.peOptionalHeader);

		header.peOptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		header.peOptionalHeader.MajorLinkerVersion = 1;
		header.peOptionalHeader.MinorLinkerVersion = 0;
		header.peOptionalHeader.SizeOfCode = aCodeSize;
		header.peOptionalHeader.SizeOfInitializedData = 0;
		header.peOptionalHeader.SizeOfUninitializedData = 0;
		header.peOptionalHeader.AddressOfEntryPoint = sizeof(FiskExeHeader);
		header.peOptionalHeader.BaseOfCode = sizeof(FiskExeHeader);
		header.peOptionalHeader.ImageBase = 0x00400000; // base addess of images
		header.peOptionalHeader.SectionAlignment = 512;
		header.peOptionalHeader.FileAlignment = 512;
		header.peOptionalHeader.MajorOperatingSystemVersion = 5;
		header.peOptionalHeader.MinorOperatingSystemVersion = 0;
		header.peOptionalHeader.MajorImageVersion = 1;
		header.peOptionalHeader.MinorImageVersion = 0;
		header.peOptionalHeader.MajorSubsystemVersion = 1;
		header.peOptionalHeader.MinorSubsystemVersion = 0;
		header.peOptionalHeader.Win32VersionValue = 0;
		header.peOptionalHeader.SizeOfImage = CeilToSmallestMultiple(sizeof(FiskExeHeader) + aCodeSize,header.peOptionalHeader.SectionAlignment);
		header.peOptionalHeader.SizeOfHeaders = CeilToSmallestMultiple(sizeof(FiskExeHeader) - offsetof(IMAGE_DOS_HEADER, e_lfanew),header.peOptionalHeader.FileAlignment);
		header.peOptionalHeader.CheckSum = 0;
		header.peOptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI; // Attach a console IMAGE_SUBSYSTEM_WINDOWS_GUI to not
		header.peOptionalHeader.DllCharacteristics = NULL;
		header.peOptionalHeader.SizeOfStackReserve = stackSize;
		header.peOptionalHeader.SizeOfStackCommit = stackCommitedSize;
		header.peOptionalHeader.SizeOfHeapReserve = heapSize;
		header.peOptionalHeader.SizeOfHeapCommit = heapSizeCommited;
		header.peOptionalHeader.LoaderFlags = 0; //obsolete
		header.peOptionalHeader.NumberOfRvaAndSizes = 0; //i'll figure this out later
	}

	std::ofstream file;
	file.open(aFilename, std::ios::binary | std::ios::out);

	file.write(reinterpret_cast<char*>(&header), sizeof(header));
	file.write(aCode, aCodeSize);
}

int main()
{
	using namespace ByteSuffixes;
	std::stringstream machineCode;

	std::string compiledCode = machineCode.str();
	ExportMachineCode(compiledCode.c_str(), compiledCode.size(), "42.exe");


    std::cout << "Hello World!\n";
}

