/*
 * Copyright (C) 2015-2019 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef _STDARAG_H_
#define _STDARAG_H_

/*
 * When clang-cl compiles under windows environment it has a few optimizations 
 * that break when variadic functions are in use: 
 * Variadic functions are never inlined with gcc and msvc but they could be with
 * clang. For this to happen the variadic function should not access the vaargs.
 * Clang relies on the use of the buitltins below to get informed.
 * If we do not use those, clang breaks and inlines code that should not get 
 * inlined
 */
#ifdef __clang__

typedef __builtin_va_list va_list;
typedef va_list __va_list;

# define va_start(_ap_,_x_)  __builtin_va_start(_ap_,_x_)
# define va_end(_ap_)        __builtin_va_end(_ap_)
# define va_arg(_ap_,_t_)    __builtin_va_arg(_ap_, _t_)
# define va_copy(dest, src) (dest = src)

#else

#include <stdint.h>

#ifndef _VA_LIST_DEFINED
typedef char*  va_list;
# define _VA_LIST_DEFINED
#endif
#ifndef __GNUC__
typedef va_list __va_list;
#endif

#ifdef  __cplusplus
extern "C" {
#endif
/* Builtin intrinsic function */
extern void __cdecl __va_start(va_list *, ...);
#ifdef  __cplusplus
}
#endif

#define _MACHINE_WORD ( sizeof(void*) )
#define _ALIGN_ADDR_TO_MACHINE_WORD(ptr,v) ( ( (uintptr_t)ptr + sizeof(v) + _MACHINE_WORD - 1 ) & ~( _MACHINE_WORD - 1 ) )
#define _ADVANCE_PTR_AND_RETURN_PREVIOUS(ptr,sz) ( ( ptr += sz ) - sz )

#define va_arg0(ap,t,sz)    ( *(t *) _ADVANCE_PTR_AND_RETURN_PREVIOUS(ap,(sz)))

#if defined(TARGET_IA32)
# define va_start(ap,v)  ( ap = (va_list)_ALIGN_ADDR_TO_MACHINE_WORD(&(v),v) )
# define va_arg(ap,t)    va_arg0(ap,t,_ALIGN_ADDR_TO_MACHINE_WORD(0,t))
#elif defined(TARGET_IA32E)
# define va_start(ap, x) __va_start(&ap, x)
# define va_arg(ap,t)    ( ( sizeof(t) > _MACHINE_WORD || ( sizeof(t) & (sizeof(t) - 1) ) != 0 ) ? *va_arg0(ap,t*,_MACHINE_WORD) : va_arg0(ap,t,_MACHINE_WORD) )
#else
# error Unsupported architecture
#endif

#define va_end(ap)      ( ap = (va_list)0 )
#define va_copy(dest, src) (dest = src)

#endif // __clang__

#endif // _STDARAG_H_


