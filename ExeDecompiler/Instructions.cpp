#include "Instructions.h"
#include <iostream>
#include "ConsoleHelpers.h"

namespace Instructions
{
	void BaseLabelPusher(const char* name, size_t virtualAddress)
	{

	}


	PushLabelFunction LabelPusher = &BaseLabelPusher;

	void SetPushLabelFunction(PushLabelFunction functionnToCall)
	{
	}

	size_t Unkown(byte* InstructionBase, byte opCode)
	{
		MakeConsoleRed();
		std::cout << "Unkown Instruction: ";
		ResetConsole();
		BinaryDump(reinterpret_cast<char*>(InstructionBase), 4);
		std::cout << std::endl;
		return -1;
	}

	size_t JMP(byte* InstructionBase, byte opCode)
	{
		std::cout << "JMP ";
		switch (opCode)
		{
		case 0xE9:
		{
			WORD* offset = reinterpret_cast<WORD*>(InstructionBase);
			byte* targetLocation = InstructionBase + 2 + *offset;

			//LabelPusher("JMP Near", targetLocation);

			std::cout << "NEAR " << (*offset > 0 ? "+" : "") << std::to_string(*offset) << " (0x" << std::hex << reinterpret_cast<size_t>(targetLocation) << std::dec << ")" << std::endl;
		}
			return 2;
		default:
			std::cout << "Unkown jmp type";
			return -1;
		}

		std::cout << std::endl;
		return 0;
	}
}