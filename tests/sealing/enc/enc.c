// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/corelibc/stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "sealing_t.h"

oe_result_t seal_data(
    oe_seal_policy_t policy,
    const char* plaintext,
    const char* aad,
    uint8_t* blob,
    size_t blob_max_size,
    size_t* blob_size)
{
    oe_result_t result = OE_OK;
    uint8_t* key_info = NULL;
    size_t ki_size = 0;
    uint8_t* b = NULL;
    size_t b_size;

    OE_CHECK(oe_get_seal_key_info(policy, NULL, 0, 0, &key_info, &ki_size));

    OE_CHECK(oe_seal(key_info, ki_size,
                     (const uint8_t*)plaintext, strlen(plaintext),
                     (const uint8_t*)aad, strlen(aad),
                     &b, &b_size));

    if (b_size > blob_max_size)
        result = OE_BUFFER_TOO_SMALL;
    else
    {
        OE_CHECK(oe_memcpy_s(blob, blob_max_size, b, b_size));
        *blob_size = b_size;
    }

done:
    if (key_info != NULL)
        oe_free_seal_key(NULL, key_info);
    if (b != NULL)
        oe_free(b);
    return result;
}

oe_result_t unseal_data(
    uint8_t* blob,
    size_t blob_size,
    size_t* plaintext_offset,
    size_t* plaintext_size,
    size_t* aad_offset,
    size_t* aad_size)
{
    oe_result_t result = OE_OK;
    uint8_t *plaintext, *aad;

    OE_CHECK(oe_unseal(blob, blob_size,
                       &plaintext, plaintext_size, &aad, aad_size));

    *plaintext_offset = (size_t)(plaintext - blob);
    *aad_offset = (size_t)(aad - blob);

done:
    return result;
}

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* Debug */
    512,  /* NumHeapPages */
    512,  /* NumStackPages */
    1);   /* NumTCS */
