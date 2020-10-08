// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/error.h>
#include "sealing_u.h"

static oe_enclave_t *_create_enclave(const char *path)
{
    static const uint32_t flags = oe_get_create_flags();
    oe_enclave_t *enclave;
    oe_result_t result;

    result = oe_create_sealing_enclave(path, OE_ENCLAVE_TYPE_SGX, flags,
                                       NULL, 0, &enclave);
    if (result != OE_OK)
        oe_put_err("creating enclave \'%s\'\n", path);
    return enclave;
}

static void _test_seal_unseal(oe_enclave_t *e1, oe_enclave_t *e2,
                              oe_seal_policy_t policy,
                              const char *plain, const char *aad,
                              oe_result_t expectation)
{
    oe_result_t ret;
    uint8_t blob[0x1000];
    size_t size, p_off, p_size, aad_off, aad_size;

    if (seal_data(e1, &ret, policy, plain, aad, blob, sizeof(blob), &size))
        oe_put_err("making ecall seal_data()\n");
    if (ret)
        oe_put_err("seal_data(plain=\"%s\", aad=\"%s\") returned %d\n",
                   plain, aad, ret);

    if (unseal_data(e2, &ret, blob, size,
                    &p_off, &p_size, &aad_off, &aad_size))
        oe_put_err("making ecall unseal_data()\n");
    if (ret != expectation)
        oe_put_err("unseal_data(plain=\"%s\", aad=\"%s\") returned %d\n",
                   plain, aad, ret);

    if (ret == OE_OK)
    {
        OE_TEST(p_size == strlen(plain));
        OE_TEST(memcmp(blob + p_off, plain, p_size) == 0);
        OE_TEST(aad_size == strlen(aad));
        OE_TEST(memcmp(blob + aad_off, aad, aad_size) == 0);
    }
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4)
        oe_put_err("Usage: %s <enc_seal> <enc_unseal> [0|1]", argv[0]);

    oe_enclave_t *e1 = _create_enclave(argv[1]);
    oe_enclave_t *e2 = _create_enclave(argv[2]);

    if (argc == 3)
    {
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_UNIQUE, "", "",
                          strcmp(argv[1], argv[2]) ? OE_CRYPTO_ERROR : OE_OK);
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_UNIQUE, "plain", "",
                          strcmp(argv[1], argv[2]) ? OE_CRYPTO_ERROR : OE_OK);
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_UNIQUE, "", "aad",
                          strcmp(argv[1], argv[2]) ? OE_CRYPTO_ERROR : OE_OK);
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_UNIQUE, "plaintext", "aad",
                          strcmp(argv[1], argv[2]) ? OE_CRYPTO_ERROR : OE_OK);
    }
    else
    {
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_PRODUCT, "", "",
                          atoi(argv[3]) ? OE_OK : OE_CRYPTO_ERROR);
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_PRODUCT, "plaintext", "",
                          atoi(argv[3]) ? OE_OK : OE_CRYPTO_ERROR);
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_PRODUCT, "", "aad",
                          atoi(argv[3]) ? OE_OK : OE_CRYPTO_ERROR);
        _test_seal_unseal(e1, e2, OE_SEAL_POLICY_PRODUCT, "plaintext", "aad",
                          atoi(argv[3]) ? OE_OK : OE_CRYPTO_ERROR);
    }
    return 0;
}
