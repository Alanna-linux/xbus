/**
 * log2.h
 *
 * Copyright (C) 2022 zhujiongfu <zhujiongfu@live.cn>
 * Creation Date: Dec 07, 2022
 *
 */

#ifndef _LOG2_H
#define _LOG2_H

#include "bitops.h"

static inline __attribute__((const))
int is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

static inline __attribute__((const))
unsigned long roundup_pow_of_two(unsigned long n)
{
	return 1UL << fls_long(n - 1);
}

static inline __attribute__((const))
unsigned long rounddown_pow_of_two(unsigned long n)
{
	return 1UL << (fls_long(n) - 1);
}

#endif
