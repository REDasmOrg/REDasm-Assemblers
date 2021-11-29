#pragma once

#define ARM32LE_USERDATA "arm32le_userdata"
#define ARM32BE_USERDATA "arm32be_userdata"

#define THUMBLE_ID "thumble"
#define THUMBBE_ID "thumbbe"
#define ARM32LE_ID "arm32le"
#define ARM32BE_ID "arm32be"

#define ARM_IS_THUMB(address) (address & 1)
#define ARM_PC(address)       (address & ~1)
