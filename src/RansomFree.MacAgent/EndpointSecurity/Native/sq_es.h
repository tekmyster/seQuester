#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Private transport ABI, not Apple enum values or structure layouts.
// Caller serializes open/read/close. No callback crosses this boundary.
uint32_t sq_es_abi(void);
int32_t sq_es_open(void **handle);
// Returns byte count, 0 for empty, -1 for invalid arguments. Loss is incremental.
int32_t sq_es_read(void *handle, uint8_t *bytes, uint32_t capacity, uint64_t *loss);
// Consumes handle even on error. Error permanently disables new clients in this process.
int32_t sq_es_close(void *handle);
#ifdef __cplusplus
}
#endif
