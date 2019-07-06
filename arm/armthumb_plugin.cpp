#include "arm/arm_thumb.h"
#include <redasm/context.h>

REDASM_ASSEMBLER("ARM Thumb", "Dax", "MIT", 1)
REDASM_LOAD { armthumb.plugin = new ARMThumbAssembler(); return true; }
REDASM_UNLOAD { armthumb.plugin->release(); }
