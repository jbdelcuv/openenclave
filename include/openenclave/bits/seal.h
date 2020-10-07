// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file seal.h
 *
 * This file defines constants and structures for sealing APIs.
 *
 * Only TEE agnostic definitions should go to this file. SGX specific
 * definitions should go to sgx/seal.h
 */

#ifndef _OE_BITS_SEAL_H
#define _OE_BITS_SEAL_H

#define OE_SEAL_TEE_AGNOSTIC    0

#if __x86_64__ || _M_X64
#include <openenclave/bits/sgx/seal.h>
#endif

#endif /* _OE_BITS_SEAL_H */
