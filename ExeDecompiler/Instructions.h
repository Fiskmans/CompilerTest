#pragma once
#include <Windows.h>

namespace Instructions
{
	typedef void (*PushLabelFunction)(const char* name, size_t virtAddress);

	void SetPushLabelFunction(PushLabelFunction functionnToCall);

	size_t Unkown(byte* InstructionBase, byte opCode);

	size_t JMP(byte* InstructionBase, byte opCode);
}