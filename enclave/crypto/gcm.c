// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/cipher.h>

#include <openenclave/internal/raise.h>
#include <openenclave/internal/crypto/gcm.h>

oe_result_t oe_aes_gcm_encrypt(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* iv,
    size_t iv_size,
    const uint8_t* aad,
    size_t aad_size,
    const uint8_t* input,
    size_t inlen,
    uint8_t* output,
    uint8_t* tag)
{
    const mbedtls_cipher_info_t *info;
    mbedtls_cipher_context_t gcm;
    oe_result_t result = OE_OK;
    size_t olen;

    if (key_size != 16)
        return OE_UNSUPPORTED;

    mbedtls_cipher_init(&gcm);

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
    if (info == NULL ||
        mbedtls_cipher_setup(&gcm, info) ||
        mbedtls_cipher_setkey(&gcm, key, (int)key_size * 8, MBEDTLS_ENCRYPT) ||
        mbedtls_cipher_auth_encrypt(&gcm, iv, iv_size, aad, aad_size, input, inlen,
                                    output, &olen, tag, 16))
        result = OE_CRYPTO_ERROR;

    mbedtls_cipher_free(&gcm);
    return result;
}

oe_result_t oe_aes_gcm_decrypt(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* iv,
    size_t iv_size,
    const uint8_t* aad,
    size_t aad_size,
    uint8_t* inout,
    size_t inout_size,
    const uint8_t* tag)
{
    const mbedtls_cipher_info_t *info;
    mbedtls_cipher_context_t gcm;
    oe_result_t result = OE_OK;
    size_t olen;

    if (key_size != 16)
        return OE_UNSUPPORTED;

    mbedtls_cipher_init(&gcm);

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
    if (info == NULL ||
        mbedtls_cipher_setup(&gcm, info) ||
        mbedtls_cipher_setkey(&gcm, key, (int)key_size * 8, MBEDTLS_DECRYPT) ||
        mbedtls_cipher_auth_decrypt(&gcm, iv, iv_size, aad, aad_size, inout, inout_size,
                                    inout, &olen, tag, 16))
        result = OE_CRYPTO_ERROR;

    mbedtls_cipher_free(&gcm);
    return result;
}
