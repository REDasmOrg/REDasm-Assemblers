#include <redasm/redasm.h>
#include "xtensa.h"

REDASM_ASSEMBLER("Tensilica Xtensa", "Dax", "MIT", 1)
REDASM_LOAD { xtensa.plugin = new XtensaAssembler(); return true; }
REDASM_UNLOAD { xtensa.plugin->release(); }
