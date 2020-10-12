
#include <iostream>
#include <string>
#include <fstream>
#include <Windows.h>
#include <vector>
#include <time.h>
#include <iomanip>
#include <unordered_map>
#include <bitset>
#include <functional>
#include <array>
#include "Instructions.h"
#include "ConsoleHelpers.h"


bool isLegacyPrefix(byte aByte)
{
	const std::unordered_map<byte, std::string> prefixes =
	{
		{0x66,"[16] "},
		{0x67,"[32] "},
		{0x2E,"[CE] "},
		{0x3E,"[DS] "},
		{0x26,"[ES] "},
		{0x64,"[FS] "},
		{0x65,"[GS] "},
		{0x36,"[SS] "},
		{0xF0,"[Lock] "},
		{0xF3,"[Repeat until false] "}, //on cmpstr and scanstr
		{0xF2,"[Repeat until true] "} //on cmpstr and scanstr
	};
	auto it = prefixes.find(aByte);
	if (it != prefixes.end())
	{
		std::cout << it->second;
		return true;
	}
	return false;
}


bool isREXPrefix(byte aByte)
{
	byte low = aByte & 0x0F;
	byte high = (aByte & 0xF0) >> 4;
	if (high == 0x04)
	{
		std::cout << "[Something REX] ";
		return true;
	}

	return false;
}

bool isVEXPrefix(byte aByte)
{

	return false;
}

size_t VexTable(byte* aVEXBase)
{
	MakeConsoleRed();
	std::cout << "Unkown Vex opCode" << std::endl;
	ResetConsole();
	return -1;
}

bool isXOPPrefix(byte aByte)
{

	return false;
}

size_t XOPTable(byte* aXOPBase)
{
	MakeConsoleRed();
	std::cout << "Unkown XOP opCode" << std::endl;
	ResetConsole();
	return -1;
}

size_t OFEscape(byte* escapeBase)
{

	MakeConsoleRed();
	std::cout << "Unkown escape sequence" << std::endl;
	ResetConsole();
	return -1;
}

typedef size_t InstructionFunction(byte* InstructionBase,byte opCode);

size_t ModRM(byte opCode, byte* modrmBase)
{
	byte mod = ((*modrmBase) >> 6) & 0x03;
	byte reg = ((*modrmBase) >> 3) & 0x07;
	byte rm = (*modrmBase) & 0x03;

	const std::unordered_map<byte, std::array<std::function<InstructionFunction>, 8>> instructions =
	{

	};

	auto it = instructions.find(opCode);
	if (it != instructions.end())
	{
		size_t instructionSize = it->second[reg](modrmBase+1,opCode);
		if (instructionSize == -1)
		{
			return -1;
		}
		return instructionSize + 1;
	}
	else
	{
		std::cout << "Invalid modrm base opcode " << std::endl;
		return -1;
	}
}



size_t PrimaryOPCodeMap(byte* OPCodeBase)
{
	byte lowNibble = ((*OPCodeBase) & 0x0F);
	byte highNibble = ((*OPCodeBase) & 0xF0) >> 4;

	if (lowNibble > 0x0F ||highNibble > 0x0F)
	{
		std::cout << "my math is way off" << std::endl;
		return -1;
	}

	using namespace Instructions;


	const std::array<std::array<std::function<InstructionFunction>, 0x10>, 0x10> opcodeMap = 
	{
/*		0			1			2			3			4			5			6			7			8			9			A			B			C			D			E			F
/*0*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*1*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*2*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*3*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*4*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*5*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*6*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*7*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*8*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*9*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*A*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*B*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*C*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*D*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,
/*E*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	&JMP,		&JMP,		&JMP,		nullptr,	nullptr,	nullptr,	nullptr,
/*F*/	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr,	nullptr
	};

	if (!opcodeMap[highNibble][lowNibble])
	{
		MakeConsoleRed();
		std::cout << "Unkown primary opcode: ";
		ResetConsole();
		BinaryDump(reinterpret_cast<char*>(OPCodeBase), 4);
		std::cout << std::endl;
		return -1;
	}

	size_t instructionSize = opcodeMap[highNibble][lowNibble](OPCodeBase + 1, *OPCodeBase);
	if (instructionSize == -1)
	{
		return -1;
	}
	return instructionSize + 1;


	return -1;
}

size_t DecodeInstruction(byte* InstructionBase)
{
	byte* at = InstructionBase;

	while (isLegacyPrefix(*at))
	{
		at++;
		if (at - InstructionBase > 4)
		{
			std::cout << "Too many legacy prefixes machine code is invalid" << std::endl;
			return -1;
		}
	}

	bool hasRexPrefix = false;
	if (isREXPrefix(*at))
	{
		at++;
		hasRexPrefix = true;
	}

	if (*at == 0x0F)
	{
		size_t escapeSize = OFEscape(at);
		if (escapeSize == -1)
		{
			return -1;
		}
		at += escapeSize;
		return at - InstructionBase;
	}

	if (!hasRexPrefix)
	{
		if (isVEXPrefix(*at))
		{
			at++;
			size_t vexSize = VexTable(at);
			if (vexSize == -1)
			{
				return -1;
			}
			at += vexSize;
			return at - InstructionBase;
		}

		if (isXOPPrefix(*at))
		{
			at++;
			size_t xopSize = XOPTable(at);
			if (xopSize == -1)
			{
				return -1;
			}
			at += xopSize;
			return at - InstructionBase;
		}
	}

	size_t primaryopSize = PrimaryOPCodeMap(at);
	if (primaryopSize == -1)
	{
		return -1;
	}
	at += primaryopSize;
	return at - InstructionBase;


}

void Explorex64MachineCode(byte* rawData, size_t aDataSize, size_t aEntrypoint)
{
	byte* execPointer = rawData + aEntrypoint;
	while (execPointer-rawData < aDataSize)
	{
		size_t instructionSize = DecodeInstruction(execPointer);
		if (instructionSize == -1)
		{
			std::cout << "Instruction size invalid ";
			MakeConsoleRed();
			std::cout << "ENDING" << std::endl;
			ResetConsole();


			std::cout << "Failed instruction: ";
			BinaryDump(reinterpret_cast<char*>(execPointer), 15);
			std::cout << std::endl;
			break;
		}
		execPointer += instructionSize;

		if (execPointer - rawData + 15 > aDataSize)
		{
			std::cout << "execution is too close to end of data and could buffer overflow.";
			MakeConsoleRed();
			std::cout << "ENDING" << std::endl;
			ResetConsole();
		}
	}
	std::cout << "Program over" << std::endl;
}

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


		std::cout << "\tMagic number:\t\t\t0x"		<< std::hex << dosheader.e_magic << "\t" << std::string(reinterpret_cast<char*>(&dosheader.e_magic),sizeof(dosheader.e_magic)) << std::endl;
		std::cout << "\tBytes on last page:\t\t0x"	<< std::hex << dosheader.e_cblp << std::dec << std::endl;
		std::cout << "\tPages in file:\t\t\t"		<< dosheader.e_cp << std::endl;
		std::cout << "\tRelocations:\t\t\t"			<< dosheader.e_crlc << std::endl;
		std::cout << "\tHeader size (paragraphs):\t" << dosheader.e_cparhdr << std::endl;
		std::cout << "\tMinimum extra paragraphs:\t" << dosheader.e_minalloc << std::endl;
		std::cout << "\tMaximum extra paragraphs:\t" << dosheader.e_maxalloc << std::endl;
		std::cout << "\tSS value:\t\t\t0x"			<< dosheader.e_ss << std::endl;
		std::cout << "\tSP value:\t\t\t0x"			<< dosheader.e_sp << std::endl;
		std::cout << "\tChecksum:\t\t\t0x"			<< std::hex << dosheader.e_csum << std::dec << std::endl;
		std::cout << "\tIP value:\t\t\t"			<< dosheader.e_ip << std::endl;
		std::cout << "\tCS value:\t\t\t"			<< dosheader.e_cs << std::endl;
		std::cout << "\tAddress of relocation:\t\t0x" << std::hex << dosheader.e_lfarlc << std::dec << std::endl;
		std::cout << "\tOverlay number:\t\t\t"		<< dosheader.e_ovno << std::endl;
		for (size_t i = 0; i < 4; i++)
		{
			std::cout << "\tReserved " + std::to_string(i) + ":\t\t\t" << dosheader.e_res[i] << std::endl;
		}
		std::cout << "\tOEM id:\t\t\t\t"			<< dosheader.e_oemid << std::endl;
		std::cout << "\tOEM info:\t\t\t"			 << dosheader.e_oeminfo << std::endl;
		for (size_t i = 0; i < 10; i++)
		{
			std::cout << "\tReserved second " + std::to_string(i) + ":\t\t" << dosheader.e_res2[i] << std::endl;
		}
		std::cout << "\tNew Pe header location:\t\t0x" << std::hex << dosheader.e_lfanew << std::dec << std::endl << std::endl;


		size_t byteDistanceToPE = dosheader.e_lfanew - sizeof(IMAGE_DOS_HEADER);

		std::vector<char> dosStubPerhaps;
		dosStubPerhaps.resize(byteDistanceToPE);
		inputFile.read(reinterpret_cast<char*>(dosStubPerhaps.data()), byteDistanceToPE);

		std::cout << "Data padding dump:" << std::endl;

		BinaryDump(reinterpret_cast<char*>(dosStubPerhaps.data()),dosStubPerhaps.size());


		UWORD signatureShort;
		unsigned int signature;
		inputFile.read(reinterpret_cast<char*>(&signatureShort), sizeof(signatureShort));

		if (signatureShort == IMAGE_DOS_SIGNATURE)
		{
			MakeConsoleRed();
			std::cout << "PE is a dos executable, stopping decompiling" << std::endl;
			ResetConsole();
			return;
		}

		if (signatureShort == IMAGE_OS2_SIGNATURE)
		{
			MakeConsoleRed();
			std::cout << "PE is a os2 executable, stopping decompiling" << std::endl;
			ResetConsole();
			return;
		}
		if (signatureShort == IMAGE_OS2_SIGNATURE_LE)
		{
			MakeConsoleRed();
			std::cout << "PE is a os2_le executable, stopping decompiling" << std::endl;
			ResetConsole();
			return;
		}
		if (signatureShort == IMAGE_VXD_SIGNATURE)
		{
			MakeConsoleRed();
			std::cout << "PE is a vxd executable, stopping decompiling" << std::endl;
			ResetConsole();
			return;
		}


		memcpy(reinterpret_cast<char*>(&signature), reinterpret_cast<char*>(&signatureShort), sizeof(signatureShort));
		inputFile.read(reinterpret_cast<char*>(&signature) + sizeof(signatureShort), sizeof(signature) - sizeof(signatureShort));

		if (signature == IMAGE_NT_SIGNATURE)
		{
			MakeConsoleGreen();
			std::cout << "PE is a NT executable" << std::endl;
			ResetConsole();
		}
		else
		{
			MakeConsoleRed();
			std::cout << "PE is not a NT executable, stopping decompiling" << std::endl;
			ResetConsole();
			return;
		}


		IMAGE_FILE_HEADER peHeader;
		inputFile.read(reinterpret_cast<char*>(&peHeader), sizeof(peHeader));

		std::cout << "PE Header:" << std::endl;


		std::unordered_map<WORD, std::string> machineNames =
		{
			{IMAGE_FILE_MACHINE_UNKNOWN		, "UNKNOWN		"},
			{IMAGE_FILE_MACHINE_TARGET_HOST	, "TARGET_HOST	"},
			{IMAGE_FILE_MACHINE_I386		, "I386			"},
			{IMAGE_FILE_MACHINE_R3000		, "R3000		"},
			{IMAGE_FILE_MACHINE_R4000		, "R4000		"},
			{IMAGE_FILE_MACHINE_R10000		, "R10000		"},
			{IMAGE_FILE_MACHINE_WCEMIPSV2	, "WCEMIPSV2	"},
			{IMAGE_FILE_MACHINE_ALPHA		, "ALPHA		"},
			{IMAGE_FILE_MACHINE_SH3			, "SH3			"},
			{IMAGE_FILE_MACHINE_SH3DSP		, "SH3DSP		"},
			{IMAGE_FILE_MACHINE_SH3E		, "SH3E			"},
			{IMAGE_FILE_MACHINE_SH4			, "SH4			"},
			{IMAGE_FILE_MACHINE_SH5			, "SH5			"},
			{IMAGE_FILE_MACHINE_ARM			, "ARM			"},
			{IMAGE_FILE_MACHINE_THUMB		, "THUMB		"},
			{IMAGE_FILE_MACHINE_ARMNT		, "ARMNT		"},
			{IMAGE_FILE_MACHINE_AM33		, "AM33			"},
			{IMAGE_FILE_MACHINE_POWERPC		, "POWERPC		"},
			{IMAGE_FILE_MACHINE_POWERPCFP	, "POWERPCFP	"},
			{IMAGE_FILE_MACHINE_IA64		, "IA64			"},
			{IMAGE_FILE_MACHINE_MIPS16		, "MIPS16		"},
			{IMAGE_FILE_MACHINE_ALPHA64		, "ALPHA64		"},
			{IMAGE_FILE_MACHINE_MIPSFPU		, "MIPSFPU		"},
			{IMAGE_FILE_MACHINE_MIPSFPU16	, "MIPSFPU16	"},
			{IMAGE_FILE_MACHINE_AXP64		, "AXP64		"},
			{IMAGE_FILE_MACHINE_TRICORE		, "TRICORE		"},
			{IMAGE_FILE_MACHINE_CEF			, "CEF			"},
			{IMAGE_FILE_MACHINE_EBC			, "EBC			"},
			{IMAGE_FILE_MACHINE_AMD64		, "AMD64		"},
			{IMAGE_FILE_MACHINE_M32R		, "M32R			"},
			{IMAGE_FILE_MACHINE_ARM64		, "ARM64   (x64)"},
			{IMAGE_FILE_MACHINE_CEE			, "CEE			"}
		};

		if (machineNames.count(peHeader.Machine) != 0)
		{
			std::cout << "\tMachine: \t\t";
			if (peHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			{
				MakeConsoleGreen();
			}
			std::cout << machineNames[peHeader.Machine] << std::endl;
			ResetConsole();
		}
		else
		{
			std::cout << "\tMachine: Completely unkown" << std::endl;
		}

		std::cout << "\tSection count:\t\t" << peHeader.NumberOfSections << std::endl;

		std::tm time;
		localtime_s(&time,reinterpret_cast<time_t*>(&peHeader.TimeDateStamp));
		std::cout << "\tCompiled at:\t\t" << std::put_time(&time, "%Y-%m-%d %I:%M:%S %p") << std::endl;


		std::cout << "\tSymbol table location:\t0x" << std::hex << peHeader.PointerToSymbolTable << std::dec << std::endl;
		std::cout << "\tSymbol count:\t\t" << peHeader.NumberOfSections << std::endl;
		std::cout << "\tOptional Header size:\t" << peHeader.SizeOfOptionalHeader << std::endl;
		std::cout << "\tCharacteristics:\t";

		std::unordered_map<WORD, std::string> CharacteristicsMap =
		{
			{IMAGE_FILE_RELOCS_STRIPPED			, "RELOCS_STRIPPED"},
			{IMAGE_FILE_EXECUTABLE_IMAGE		, "EXECUTABLE_IMAGE"},
			{IMAGE_FILE_LINE_NUMS_STRIPPED		, "LINE_NUMS_STRIPPED"},
			{IMAGE_FILE_LOCAL_SYMS_STRIPPED		, "LOCAL_SYMS_STRIPPED"},
			{IMAGE_FILE_AGGRESIVE_WS_TRIM		, "AGGRESIVE_WS_TRIM"},
			{IMAGE_FILE_LARGE_ADDRESS_AWARE		, "LARGE_ADDRESS_AWARE"},
			{IMAGE_FILE_BYTES_REVERSED_LO		, "BYTES_REVERSED_LO"},
			{IMAGE_FILE_32BIT_MACHINE			, "32BIT_MACHINE"},
			{IMAGE_FILE_DEBUG_STRIPPED			, "DEBUG_STRIPPED"},
			{IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	, "REMOVABLE_RUN_FROM_SWAP"},
			{IMAGE_FILE_NET_RUN_FROM_SWAP		, "NET_RUN_FROM_SWAP"},
			{IMAGE_FILE_SYSTEM					, "SYSTEM"},
			{IMAGE_FILE_DLL						, "DLL"},
			{IMAGE_FILE_UP_SYSTEM_ONLY			, "UP_SYSTEM_ONLY"},
			{IMAGE_FILE_BYTES_REVERSED_HI		, "BYTES_REVERSED_HI"}
		};
		


		bool isFirst = true;
		for (auto& charact : CharacteristicsMap)
		{
			if ((charact.first & peHeader.Characteristics) != NULL)
			{
				if (!isFirst)
				{
					std::cout << " | ";
				}
				isFirst = false;
				std::cout << charact.second;
			}
		}
		std::cout << std::endl << std::endl;

		if (peHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32))
		{
			MakeConsoleRed();
			std::cout << "Image is using 32 bit optional header, stopping decompiling" << std::endl;
			ResetConsole();
			return;
		}

		if (peHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
		{
			MakeConsoleGreen();
			std::cout << "Image is using 64 bit optional header" << std::endl;
			ResetConsole();
		}
		else
		{
			MakeConsoleRed();
			std::cout << "Image is using a unkown optional header size, stopping decompiling" << std::endl;
			ResetConsole();
			return;
		}

		IMAGE_OPTIONAL_HEADER64 optHeader;

		inputFile.read(reinterpret_cast<char*>(&optHeader), sizeof(optHeader));

		std::cout << "'Optional' header:" << std::endl;
		{
			std::cout << "\tMagic number:\t\t0x" << std::hex << optHeader.Magic << std::dec;
			if (optHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			{
				MakeConsoleRed();
				std::cout << " (HDR32)";
				ResetConsole();
			}
			if (optHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				MakeConsoleGreen();
				std::cout << " (HDR64)";
				ResetConsole();
			}
			if (optHeader.Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC)
			{
				MakeConsoleRed();
				std::cout << " (ROM HDR)";
				ResetConsole();
			}
			std::cout	<< std::endl;
		}

		std::cout << "\tLinkerVersion:\t\t" << int(optHeader.MajorLinkerVersion) << "." << int(optHeader.MinorLinkerVersion) << std::endl;
		std::cout << "\tCode size:\t\t0x" << std::hex << optHeader.SizeOfCode << std::dec << std::endl;
		std::cout << "\tuinit data size:\t0x" << std::hex << optHeader.SizeOfUninitializedData << std::dec << std::endl;
		std::cout << "\tinit data size:\t\t0x" << std::hex << optHeader.SizeOfInitializedData << std::dec << std::endl;
		std::cout << "\tEntrypoint:\t\t0x" << std::hex << optHeader.AddressOfEntryPoint << std::dec << std::endl;
		std::cout << "\tBase of code:\t\t0x" << std::hex << optHeader.BaseOfCode << std::dec << std::endl;
		std::cout << "\tImage base:\t\t0x" << std::hex << optHeader.ImageBase << std::dec << std::endl;
		std::cout << "\tSection alignment:\t0x" << std::hex << optHeader.SectionAlignment << std::dec << std::endl;
		std::cout << "\tFile alignment:\t\t0x" << std::hex << optHeader.FileAlignment << std::dec << std::endl;
		std::cout << "\tOs version:\t\t" << int(optHeader.MajorOperatingSystemVersion) << "." << int(optHeader.MinorOperatingSystemVersion) << std::endl;
		std::cout << "\tImage version:\t\t" << int(optHeader.MajorImageVersion) << "." << int(optHeader.MinorImageVersion) << std::endl;
		std::cout << "\tSubsystem version:\t" << int(optHeader.MajorSubsystemVersion) << "." << int(optHeader.MinorSubsystemVersion) << std::endl;
		std::cout << "\tWin32 versin:\t\t0x" << int(optHeader.Win32VersionValue) << std::endl;
		std::cout << "\tImage size:\t\t0x" << std::hex << optHeader.SizeOfImage << std::dec << std::endl;
		std::cout << "\tHeader size:\t\t0x" << std::hex << optHeader.SizeOfHeaders << std::dec << std::endl;
		std::cout << "\tChecksum:\t\t0x" << std::hex << optHeader.CheckSum << std::dec << std::endl;

		std::cout << "\tSubsystem:\t\t" << optHeader.Subsystem;
		{
			std::unordered_map<WORD, std::string> mapping =
			{
				{IMAGE_SUBSYSTEM_UNKNOWN," Unkown"},
				{IMAGE_SUBSYSTEM_NATIVE," Native"},
				{IMAGE_SUBSYSTEM_WINDOWS_GUI," Gui"},
				{IMAGE_SUBSYSTEM_WINDOWS_CUI," Cui"},
				{IMAGE_SUBSYSTEM_OS2_CUI," OS2 Cui"},
				{IMAGE_SUBSYSTEM_POSIX_CUI," Posux cui"},
				{IMAGE_SUBSYSTEM_NATIVE_WINDOWS," Native windows"},
				{IMAGE_SUBSYSTEM_WINDOWS_CE_GUI," CE CUI"},
				{IMAGE_SUBSYSTEM_EFI_APPLICATION," EFI App"},
				{IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER," EFI BOOT service driver"},
				{IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER," EFI Runtime driver"},
				{IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER," EFI ROM"},
				{IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER," XBOX"},
				{IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER," Boot app"},
				{IMAGE_SUBSYSTEM_UNKNOWN," Xbox Code catalogue"}
			};

			if (mapping.count(optHeader.Subsystem))
			{
				std::cout << mapping[optHeader.Subsystem];
			}
			else
			{
				std::cout << " something newer than this program knows";
			}
		}
		std::cout << std::endl;
		
		{
			std::cout << "\tDll characteristics:\t";
			if (optHeader.DllCharacteristics != NULL)
			{
				std::unordered_map<WORD, std::string> CharacteristicsMap =
				{
					{IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA		, "HIGH_ENTROPY_VA"},
					{IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE			, "DYNAMIC_BASE"},
					{IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY		, "FORCE_INTEGRITY"},
					{IMAGE_DLLCHARACTERISTICS_NX_COMPAT				, "NX_COMPAT"},	
					{IMAGE_DLLCHARACTERISTICS_NO_ISOLATION			, "NO_ISOLATION"},
					{IMAGE_DLLCHARACTERISTICS_NO_SEH				, "NO_SEH"},
					{IMAGE_DLLCHARACTERISTICS_NO_BIND				, "NO_BIND"},
					{IMAGE_DLLCHARACTERISTICS_APPCONTAINER			, "APPCONTAINER"},
					{IMAGE_DLLCHARACTERISTICS_WDM_DRIVER			, "WDM_DRIVER"},
					{IMAGE_DLLCHARACTERISTICS_GUARD_CF				, "GUARD_CF"},
					{IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE	, "TERMINAL_SERVER_AWARE"}
				};



				bool isFirst = true;
				for (auto& charact : CharacteristicsMap)
				{
					if ((charact.first & optHeader.DllCharacteristics) != NULL)
					{
						if (!isFirst)
						{
							std::cout << " | ";
						}
						isFirst = false;
						std::cout << charact.second;
					}
				}
			}
			else
			{
				std::cout << "None";
			}
			std::cout << std::endl;
		}

		std::cout << "\tSize of stack reserve:\t0x" << std::hex << optHeader.SizeOfStackReserve << std::dec << std::endl;
		std::cout << "\tSize of stack commit:\t0x" << std::hex << optHeader.SizeOfStackCommit<< std::dec << std::endl;
		std::cout << "\tSize of heap reserve:\t0x" << std::hex << optHeader.SizeOfHeapReserve << std::dec << std::endl;
		std::cout << "\tSize of heap commit:\t0x" << std::hex << optHeader.SizeOfHeapCommit << std::dec << std::endl;
		std::cout << "\tLoaderFlags:\t\t0x" << std::hex << optHeader.LoaderFlags << std::dec << std::endl;
		std::cout << "\tRva and size Count:\t" <<optHeader.NumberOfRvaAndSizes <<std::endl;

		std::cout << std::endl;

		size_t rvaCount = optHeader.NumberOfRvaAndSizes;


		for (size_t i = 0; i < rvaCount && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			std::cout << "Data directory [" + std::to_string(i + 1) + "]: " << std::endl;
			std::cout << "\tVirtual Address:\t0x" << std::hex << optHeader.DataDirectory[i].VirtualAddress << std::endl;
			std::cout << "\tSize:\t\t\t0x" << std::hex << optHeader.DataDirectory[i].Size << std::endl;
			std::cout << std::endl;
		}

		IMAGE_SECTION_HEADER* sectionHeaders = new IMAGE_SECTION_HEADER[peHeader.NumberOfSections];
		inputFile.read(reinterpret_cast<char*>(sectionHeaders), sizeof(IMAGE_SECTION_HEADER) * peHeader.NumberOfSections);
		size_t entrypointSection = -1;

		for (size_t i = 0; i < peHeader.NumberOfSections; i++)
		{
			std::cout << "Section [" + std::string(reinterpret_cast<char*>(sectionHeaders[i].Name), sizeof(sectionHeaders[i].Name) / sizeof(char)) + "] " + std::to_string(i + 1) + ":" << std::endl;
			
			std::cout << "\tvirtSize or Physaddress:\t0x" << std::hex << sectionHeaders[i].Misc.PhysicalAddress << std::dec << std::endl;
			std::cout << "\tvirt address:\t\t\t0x" << std::hex << sectionHeaders[i].VirtualAddress << std::dec << std::endl;
			std::cout << "\tSize of raw data:\t\t0x" << std::hex << sectionHeaders[i].SizeOfRawData << std::dec << std::endl;
			std::cout << "\traw Data location:\t\t0x" << std::hex << sectionHeaders[i].PointerToRawData << std::dec << std::endl;
			std::cout << "\trelocs count:\t\t\t0x" << std::hex << sectionHeaders[i].NumberOfRelocations << std::dec << std::endl;
			std::cout << "\trelocs location:\t\t0x" << std::hex << sectionHeaders[i].PointerToRelocations << std::dec << std::endl;
			std::cout << "\tline numbers count:\t\t0x" << std::hex << sectionHeaders[i].NumberOfLinenumbers << std::dec << std::endl;
			std::cout << "\tline numbers location:\t\t0x" << std::hex << sectionHeaders[i].PointerToLinenumbers << std::dec << std::endl;

			{

				std::cout << "\tcharacteristics:\t\t";
				if (sectionHeaders[i].Characteristics != NULL)
				{
					std::unordered_map<WORD, std::string> CharacteristicsMap =
					{
						{IMAGE_SCN_CNT_CODE					, "CNT_CODE"},
						{IMAGE_SCN_CNT_INITIALIZED_DATA		, "CNT_INITIALIZED_DATA"},
						{IMAGE_SCN_CNT_UNINITIALIZED_DATA	, "CNT_UNINITIALIZED_DATA"},
						{IMAGE_SCN_LNK_INFO					, "LNK_INFO"},
						{IMAGE_SCN_LNK_REMOVE				, "LNK_REMOVE"},
						{IMAGE_SCN_LNK_COMDAT				, "LNK_COMDAT"},
						{IMAGE_SCN_NO_DEFER_SPEC_EXC		, "NO_DEFER_SPEC_EXC"},
						{IMAGE_SCN_GPREL					, "GPREL"},
						{IMAGE_SCN_MEM_FARDATA				, "MEM_FARDATA"},
						{IMAGE_SCN_MEM_PURGEABLE			, "MEM_PURGEABLE"},
						{IMAGE_SCN_MEM_16BIT				, "MEM_16BIT"},
						{IMAGE_SCN_MEM_LOCKED				, "MEM_LOCKED"},
						{IMAGE_SCN_MEM_PRELOAD				, "MEM_PRELOAD"},
						{IMAGE_SCN_ALIGN_1BYTES   			, "ALIGN_1BYTES"},
						{IMAGE_SCN_ALIGN_2BYTES   			, "ALIGN_2BYTES"},
						{IMAGE_SCN_ALIGN_4BYTES   			, "ALIGN_4BYTES"},
						{IMAGE_SCN_ALIGN_8BYTES   			, "ALIGN_8BYTES"},
						{IMAGE_SCN_ALIGN_16BYTES  			, "ALIGN_16BYTES"},
						{IMAGE_SCN_ALIGN_32BYTES  			, "ALIGN_32BYTES"},
						{IMAGE_SCN_ALIGN_64BYTES  			, "ALIGN_64BYTES"},
						{IMAGE_SCN_ALIGN_128BYTES 			, "ALIGN_128BYTES"},
						{IMAGE_SCN_ALIGN_256BYTES 			, "ALIGN_256BYTES"},
						{IMAGE_SCN_ALIGN_512BYTES 			, "ALIGN_512BYTES"},
						{IMAGE_SCN_ALIGN_1024BYTES			, "ALIGN_1024BYTES"},
						{IMAGE_SCN_ALIGN_2048BYTES			, "ALIGN_2048BYTES"},
						{IMAGE_SCN_ALIGN_4096BYTES			, "ALIGN_4096BYTES"},
						{IMAGE_SCN_ALIGN_8192BYTES			, "ALIGN_8192BYTES"},
						{IMAGE_SCN_LNK_NRELOC_OVFL			, "LNK_NRELOC_OVFL"},
						{IMAGE_SCN_MEM_DISCARDABLE			, "MEM_DISCARDABLE"},
						{IMAGE_SCN_MEM_NOT_CACHED 			, "MEM_NOT_CACHED"},
						{IMAGE_SCN_MEM_NOT_PAGED  			, "MEM_NOT_PAGED"},
						{IMAGE_SCN_MEM_SHARED     			, "MEM_SHARED"},
						{IMAGE_SCN_MEM_EXECUTE    			, "MEM_EXECUTE"},
						{IMAGE_SCN_MEM_READ       			, "MEM_READ"},
						{IMAGE_SCN_MEM_WRITE      			, "MEM_WRITE"}
					};	 


					bool isFirst = true;
					for (auto& charact : CharacteristicsMap)
					{
						if ((charact.first & sectionHeaders[i].Characteristics) != NULL)
						{
							if (!isFirst)
							{
								std::cout << " | ";
							}
							isFirst = false;
							std::cout << charact.second;
						}
					}
				}
				else
				{
					std::cout << "None";
				}

				std::cout << std::endl;

				if (optHeader.AddressOfEntryPoint >= sectionHeaders[i].VirtualAddress && optHeader.AddressOfEntryPoint < sectionHeaders[i].VirtualAddress + sectionHeaders[i].SizeOfRawData)
				{
					MakeConsoleGreen();
					std::cout << "\tThis Section contains the entrypoint" << std::endl;
					ResetConsole();
					entrypointSection = i;
				}
			}
			std::cout << std::endl;
		}

		{
			int section = -1;
			std::cout << "Enter sectionnumber to perform binary dump on:";
			if (std::cin >> section)
			{
				if (section > peHeader.NumberOfSections || section <= 0)
				{
					if (section < 0)
					{
						std::cout << "No section selected, exploring code" << std::endl;
						if (entrypointSection != -1)
						{
							byte* rawData = new byte[sectionHeaders[entrypointSection].SizeOfRawData];
							inputFile.seekg(sectionHeaders[entrypointSection].PointerToRawData);
							inputFile.read(reinterpret_cast<char*>(rawData), sectionHeaders[entrypointSection].SizeOfRawData);

							byte* entry = rawData + optHeader.AddressOfEntryPoint - sectionHeaders[entrypointSection].PointerToRawData;

							Explorex64MachineCode(rawData, sectionHeaders[entrypointSection].SizeOfRawData,optHeader.AddressOfEntryPoint - sectionHeaders[entrypointSection].VirtualAddress);

							delete[] rawData;
						}
						else
						{
							MakeConsoleRed();
							std::cout << "No sections contained the entrypoint" << std::endl;
							ResetConsole();
						}

					}
					else
					{
						std::cout << "Invlaid index" << std::endl;
					}
				}
				else
				{
					int secindex = section - 1;
					IMAGE_SECTION_HEADER* header = sectionHeaders + secindex;


					std::cout << "Performing dataDump of section (" + std::to_string(section) + ") [" + std::string(reinterpret_cast<char*>(header->Name), sizeof(header->Name)) + "]" << std::endl;
					inputFile.seekg(header->PointerToRawData);
					char* rawData = new char[header->SizeOfRawData];
					inputFile.read(rawData, header->SizeOfRawData);
					BinaryDump(rawData, header->SizeOfRawData);
					delete[] rawData;
				}
			}
		}


		std::cout << "Press [Y] to dump dos stub to file [N] or [Enter] to Continue" << std::endl;
		while(!(GetAsyncKeyState('Y') || GetAsyncKeyState('N') || GetAsyncKeyState(VK_RETURN)));

		bool gottenKey = false;
		while (!gottenKey)
		{
			if (GetAsyncKeyState('Y'))
			{
				DumpToFile(dosStubPerhaps, "DosStub.txt");
				gottenKey = true;
			}
			gottenKey |= GetAsyncKeyState('N') || GetAsyncKeyState(VK_RETURN);
		}

	}
	else
	{
		std::cout << "Could not open file" << std::endl;
	}
}

int main(int argc, char** argv)
{
	for (size_t i = 1; i < argc; i++)
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
