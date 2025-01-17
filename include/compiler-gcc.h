#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)

#define barrier() __asm__ __volatile__("": : :"memory")

#define  noinline	__attribute__((noinline))

#define __deprecated	__attribute__((deprecated))
#define __packed	__attribute__((packed))
#define __weak		__attribute__((weak))
#define __alias(symbol)	__attribute__((alias(#symbol)))

#define __pure			__attribute__((pure))
#define __aligned(x)		__attribute__((aligned(x)))
#define __printf(a, b)		__attribute__((format(printf, a, b)))
#define __scanf(a, b)		__attribute__((format(scanf, a, b)))
#define __maybe_unused		__attribute__((unused))
#define __always_unused		__attribute__((unused))

#if GCC_VERSION < 30200
# error Sorry, your compiler is too old - please upgrade it.
#endif

#if GCC_VERSION < 30300
# define __used			__attribute__((__unused__))
#else
# define __used			__attribute__((__used__))
#endif

#if GCC_VERSION >= 30400
#define __must_check		__attribute__((warn_unused_result))
#endif

#if GCC_VERSION >= 40000

#define __used			__attribute__((__used__))
#define __compiler_offsetof(a, b)					\
	__builtin_offsetof(a, b)

#if GCC_VERSION >= 40100 && GCC_VERSION < 40600
# define __compiletime_object_size(obj) __builtin_object_size(obj, 0)
#endif

#if GCC_VERSION >= 40300

#define __cold			__attribute__((__cold__))

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

#ifndef __CHECKER__
# define __compiletime_warning(message) __attribute__((warning(message)))
# define __compiletime_error(message) __attribute__((error(message)))
#endif /* __CHECKER__ */
#endif /* GCC_VERSION >= 40300 */

#if GCC_VERSION >= 40600
#define __visible	__attribute__((externally_visible))
#endif

#if GCC_VERSION >= 70000
#define KASAN_ABI_VERSION 5
#elif GCC_VERSION >= 50000
#define KASAN_ABI_VERSION 4
#elif GCC_VERSION >= 40902
#define KASAN_ABI_VERSION 3
#endif

#if GCC_VERSION >= 40902
#define __no_sanitize_address __attribute__((no_sanitize_address))
#endif

#endif	/* gcc version >= 40000 specific checks */

#if !defined(__noclone)
#define __noclone	/* not needed */
#endif

#if !defined(__no_sanitize_address)
#define __no_sanitize_address
#endif

#define uninitialized_var(x) x = x
