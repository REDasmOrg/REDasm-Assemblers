#include "arm.h"
#include "arm_common.h"
#include <capstone/capstone.h>

ARMAssembler::ARMAssembler(): ARMCommonAssembler() { }
size_t ARMAssembler::bits() const { return 32; }

u64 ARMAssembler::pc(const Instruction *instruction) const
{
    /*
     * https://stackoverflow.com/questions/24091566/why-does-the-arm-pc-register-point-to-the-instruction-after-the-next-one-to-be-e
     *
     * In ARM state:
     *  - The value of the PC is the address of the current instruction plus 8 bytes.
     */

    return instruction->address + 8;
}

void ARMAssembler::init(const AssemblerRequest &req) { this->open(CS_ARCH_ARM, CS_MODE_ARM); }
