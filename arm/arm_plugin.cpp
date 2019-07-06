#include "arm/arm.h"
#include <redasm/context.h>

REDASM_ASSEMBLER("ARM", "Dax", "MIT", 1)
REDASM_LOAD { arm.plugin = new ARMAssembler(); return true; }
REDASM_UNLOAD { arm.plugin->release(); }
