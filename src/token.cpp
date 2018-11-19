#include "token.h"

using namespace vault;

blob_t vault::encode_token(const Authentication &authentication,
                           const blob_t &aes_key,
                           const blob_t &aes_iv,
                           const blob_t &mac_key)
{
    auto authenticationCopy = new Authentication(authentication);

    Token token;
    token.set_aes_key(aes_key.data(), aes_key.size());
    token.set_aes_iv(aes_iv.data(), aes_iv.size());
    token.set_mac_key(mac_key.data(), mac_key.size());
    token.set_allocated_authentication(authenticationCopy);

    size_t size = token.ByteSize();
    blob_t buffer(size);
    if (!token.SerializeToArray(buffer.data(), (int)size)) {
        throw std::runtime_error("failed to encode token");
    }

    return buffer;
}

void vault::decode_token(const blob_t &data,
                         Authentication &authentication,
                         blob_t &aes_key,
                         blob_t &aes_iv,
                         blob_t &mac_key)
{
    Token token;
    if (!token.ParseFromArray(data.data(), (int)data.size())) {
        throw std::runtime_error("failed to decode token");
    }
    authentication = token.authentication();
    aes_key = blob_t(token.aes_key().begin(), token.aes_key().end());
    aes_iv = blob_t(token.aes_iv().begin(), token.aes_iv().end());
    mac_key = blob_t(token.mac_key().begin(), token.mac_key().end());
}
