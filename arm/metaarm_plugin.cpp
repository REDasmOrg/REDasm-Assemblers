#include "metaarm/metaarm.h"
#include <redasm/context.h>

REDASM_ASSEMBLER("ARM/Thumb", "Dax", "MIT", 1)
REDASM_LOAD { metaarm.plugin = new MetaARMAssembler(); return true; }
REDASM_UNLOAD { metaarm.plugin->release(); }
