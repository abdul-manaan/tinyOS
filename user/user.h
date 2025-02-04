/*
 * Copyright (c) 2025 Abdul Manan
 * File created: 2025-01-19--18:19:08
 * Last modified: 2025-02-04--17:25:11
 * All rights reserved.
 */


#pragma once
#include "../common/common.h"


void putchar(char ch);
int getchar(void);
size_t freemem(void);
uint32_t uptime();
int readfile(const char *filename, char *buf, int len);
int writefile(const char *filename, const char *buf, int len);
__attribute__((noreturn)) void exit(void);