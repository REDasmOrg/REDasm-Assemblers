#pragma once

#define ARM32LE_USERDATA "arm32le_userdata"
#define ARM32BE_USERDATA "arm32be_userdata"

#define THUMBLE_ID "thumble"
#define THUMBBE_ID "thumbbe"
#define ARM32LE_ID "arm32le"
#define ARM32BE_ID "arm32be"

template<typename T>
inline T arm_is_thumb(T address) { return address & 1; }

template<typename T>
inline T arm_address(T address) { return address & ~1ull; }
