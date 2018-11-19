#ifndef VAULT_TOKEN_H
#define VAULT_TOKEN_H

#include <vault.pb.h>
#include "types.h"

namespace vault {

    blob_t encode_token(const Authentication &authentication,
                        const blob_t &aes_key,
                        const blob_t &aes_iv,
                        const blob_t &mac_key);

    void decode_token(const blob_t &data,
                      Authentication &authentication,
                      blob_t &aes_key,
                      blob_t &aes_iv,
                      blob_t &mac_key);

}

#endif // VAULT_TOKEN_H
