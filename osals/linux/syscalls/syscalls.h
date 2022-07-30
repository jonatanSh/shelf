#ifndef KERNEL_SYSCALLS_HEADER
#define KERNEL_SYSCALLS_HEADER

#if defined(__x86_64__)

#include "arch/x86_64/defs.h"
#include "arch/x86_64/syscalls.h"

#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__)

#include "arch/i386/defs.h"
#include "arch/i386/syscalls.h"

#elif defined(__ARM_EABI__)

#include "arch/arm/defs.h"
#include "arch/arm/syscalls.h"

#elif defined(__aarch64__)

#include "arch/arm64/defs.h"
#include "arch/arm64/syscalls.h"


#elif defined(__mips__) && defined(_ABIO32)

#include "arch/mips/defs.h"
#include "arch/mips/syscalls.h"

#endif

#endif //KERNEL_SYSCALLS_HEADER