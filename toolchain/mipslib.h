#pragma once

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned size_t;
typedef int ssize_t;

void exit(int code);
ssize_t write(int fd, const void *data, size_t size);
ssize_t read(int fd, void *data, size_t size);

