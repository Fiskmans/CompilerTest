#include <iostream>

#include <fstream>
#include <sstream>
#include <Windows.h>
#include <time.h>
#include <vector>


// http://www.csn.ul.ie/~caolan/pub/winresdump/winresdump/doc/pefile2.html

// https://www.amd.com/system/files/TechDocs/24594.pdf

// https://www.mitec.cz/exe.html



#define WIPE(arg) memset(&arg,0,sizeof(arg));

#pragma pack(push,0)

struct FiskExeHeader
{
	IMAGE_DOS_HEADER mzHeader;
	const char dosStub[168] = "\xe\x1f\xba\xe\x0\xb4\x9\xcd\x21\xb8\x1\x4c\xcd\x21\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20\x6d\x6f\x64\x65\x2e\xd\xd\xa\x24\x0\x0\x0\x0\x0\x0\x0\xd4\x63\x69\x2f\x90\x2\x7\x7c\x90\x2\x7\x7c\x90\x2\x7\x7c\x9b\x6d\x3\x7d\x9b\x2\x7\x7c\x9b\x6d\x4\x7d\x93\x2\x7\x7c\x9b\x6d\x2\x7d\xb0\x2\x7\x7c\x9b\x6d\x6\x7d\x96\x2\x7\x7c\xcb\x6a\x6\x7d\x97\x2\x7\x7c\x90\x2\x6\x7c\x25\x2\x7\x7c\x56\x6d\x2\x7d\x91\x2\x7\x7c\x56\x6d\xf8\x7c\x91\x2\x7\x7c\x56\x6d\x5\x7d\x91\x2\x7\x7c\x52\x69\x63\x68\x90\x2\x7\x7c\x0\x0\x0\x0\x0\x0\x0";
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
		header.mzHeader.e_maxalloc = 65535;
		header.mzHeader.e_sp = sizeof(header.dosStub);
		header.mzHeader.e_lfarlc = offsetof(FiskExeHeader, dosStub);
		header.mzHeader.e_lfanew = offsetof(FiskExeHeader, signature);

		header.signature = IMAGE_NT_SIGNATURE;
	}

	{ // PE Header
		WIPE(header.peFileHeader);

		header.peFileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
		header.peFileHeader.NumberOfSections = sectionCount;
		header.peFileHeader.TimeDateStamp = time(nullptr);
		header.peFileHeader.PointerToSymbolTable = NULL;
		header.peFileHeader.NumberOfSymbols = 0;
		header.peFileHeader.SizeOfOptionalHeader = sizeof(header.peOptionalHeader);
		header.peFileHeader.Characteristics =  IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
	}

	struct Section
	{
		IMAGE_SECTION_HEADER header;
		std::vector<char> data;

		size_t Size() const { return sizeof(header) + data.size(); }
	};

	std::vector<Section> sections;




	size_t imageSize = CeilToSmallestMultiple(sizeof(FiskExeHeader) + aCodeSize, header.peOptionalHeader.SectionAlignment);

	{ // PE Optional header
		WIPE(header.peOptionalHeader);

		header.peOptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		header.peOptionalHeader.MajorLinkerVersion = 1;
		header.peOptionalHeader.MinorLinkerVersion = 0;
		header.peOptionalHeader.SizeOfCode = aCodeSize;
		header.peOptionalHeader.SizeOfInitializedData = 0;
		header.peOptionalHeader.SizeOfUninitializedData = 0;
		header.peOptionalHeader.ImageBase = 0x00400000; // base addess of image
		header.peOptionalHeader.SectionAlignment = 512;
		header.peOptionalHeader.FileAlignment = 512;
		header.peOptionalHeader.BaseOfCode = header.peOptionalHeader.SectionAlignment; // First section
		header.peOptionalHeader.MajorOperatingSystemVersion = 5;
		header.peOptionalHeader.MinorOperatingSystemVersion = 0;
		header.peOptionalHeader.MajorImageVersion = 1;
		header.peOptionalHeader.MinorImageVersion = 0;
		header.peOptionalHeader.MajorSubsystemVersion = 1;
		header.peOptionalHeader.MinorSubsystemVersion = 0;
		header.peOptionalHeader.Win32VersionValue = 0;
		header.peOptionalHeader.SizeOfImage = imageSize;
		header.peOptionalHeader.SizeOfHeaders = CeilToSmallestMultiple(sizeof(FiskExeHeader) - offsetof(IMAGE_DOS_HEADER, e_lfanew),header.peOptionalHeader.FileAlignment);
		header.peOptionalHeader.CheckSum = 0;
		header.peOptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI; // Attach a console? IMAGE_SUBSYSTEM_WINDOWS_GUI to not
		header.peOptionalHeader.DllCharacteristics = NULL;
		header.peOptionalHeader.SizeOfStackReserve = stackSize;
		header.peOptionalHeader.SizeOfStackCommit = stackCommitedSize;
		header.peOptionalHeader.SizeOfHeapReserve = heapSize;
		header.peOptionalHeader.SizeOfHeapCommit = heapSizeCommited;
		header.peOptionalHeader.LoaderFlags = 0; //obsolete





		size_t entryPoint = -1;
		{	//[.textbss]
			Section sec;
			WIPE(sec.header);
			memcpy(sec.header.Name, ".textbss", IMAGE_SIZEOF_SHORT_NAME);
			sec.header.Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_CNT_CODE;
			sec.header.VirtualAddress = header.peOptionalHeader.SectionAlignment; // First section

			sections.push_back(sec);
		}



		{	//[.text   ]

			Section sec;
			WIPE(sec.header);
			memcpy(sec.header.Name, ".text   ", IMAGE_SIZEOF_SHORT_NAME);
			sec.header.Characteristics = IMAGE_SCN_CNT_CODE;
			sec.header.VirtualAddress = header.peOptionalHeader.SectionAlignment * 2; // second section



			sections.push_back(sec);
		}





		header.peOptionalHeader.AddressOfEntryPoint = entryPoint;
		header.peFileHeader.NumberOfSections = sections.size();
	}


	size_t sectionHeadersSize = 0;
	size_t sectionDataSize = 0;
	for (auto& sec : sections)
	{
		sectionHeadersSize += sizeof(sec.header);
		sectionDataSize += sec.data.size();
	}

	size_t totalFileSize = sizeof(header) + sectionHeadersSize + sectionDataSize;

	size_t sectionHeaderOffset = sizeof(header);
	size_t sectionDataOffset = sectionHeaderOffset + sectionHeadersSize;

	byte* rawData = new byte[totalFileSize];

	memcpy(rawData, &header, sizeof(header));



	std::ofstream file;
	file.open(aFilename, std::ios::binary | std::ios::out);


	file.write(reinterpret_cast<char*>(&header), sizeof(header));

	for (auto& i : sections)
	{

	}
}

int main()
{
	using namespace ByteSuffixes;
	std::stringstream machineCode;

	machineCode << '\xC3'; // RET

	std::string compiledCode = machineCode.str();
	ExportMachineCode(compiledCode.c_str(), compiledCode.size(), "42.exe");


    std::cout << "Hello World!\n";
	printf("Hello World!\n");
}

