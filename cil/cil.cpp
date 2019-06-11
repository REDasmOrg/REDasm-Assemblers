#include "cil.h"

CILAssembler::CILAssembler(): Assembler() { }
size_t CILAssembler::bits() const { return 32; }
bool CILAssembler::decodeInstruction(const BufferView& view, const InstructionPtr &instruction) { return false; }

REDASM_ASSEMBLER("CIL/MSIL", "Dax", "MIT", 1)
REDASM_LOAD { cil.plugin = new CILAssembler(); return true; }
REDASM_UNLOAD { cil.plugin->release(); }
