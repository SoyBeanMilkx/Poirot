#ifndef POIROT_CORE_HOOK_H
#define POIROT_CORE_HOOK_H

#include <stdint.h>

#define POIROT_HOOK_BIAS UINT64_C(17)
#define POIROT_HOOK_CANARY UINT64_C(0x504f49524f54584a)

uint64_t hook_control(uint64_t input);

#endif
