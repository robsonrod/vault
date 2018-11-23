
#include <vault.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include "vault.pb.h"
#include "rand.h"
#include "secret.h"
#include "aes.h"
#include "token.h"

const int AES_KEY_SIZE = 32;
const int IV_SIZE = 16;
const int SALT_SIZE = 16;
const int HMAC_KEY_SIZE = 64;

using namespace std;
using namespace vault;

static blob_t make_blob(const string &str) {
    return blob_t(str.begin(), str.end());
}

static string tohex(const blob_t &blob) {
    std::string hex_tmp;
    for (auto x : blob) {
        ostringstream oss;
        oss << hex << setw(2) << setfill('0') << (unsigned)x;
        hex_tmp += oss.str();
    }
    return hex_tmp;
}

token_t vault::create(const string &path, const string &password, const string &key, const userdata_t &userdata)
{
    blob_t salt = rand(SALT_SIZE);
    const int secret_size = AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE;
    int iterations = estimate_iterations(password, salt, secret_size);
    blob_t secret = generate_secret(password, salt, iterations, secret_size);

    blob_t aes_key(secret.cbegin(), secret.cbegin() + AES_KEY_SIZE);
    blob_t aes_iv(secret.cbegin() + AES_KEY_SIZE, secret.cbegin() + AES_KEY_SIZE + IV_SIZE);
    blob_t mac_key(secret.cbegin() + AES_KEY_SIZE + IV_SIZE, secret.cend());
    blob_t encrypted = encrypt(userdata, aes_key, aes_iv);

    blob_t tmp(encrypted.begin(), encrypted.end());
    tmp.insert(tmp.end(), secret.begin(), secret.end());
    blob_t hmac = calc_hmac(tmp, HMAC_KEY_SIZE);

    auto authentication = new Authentication;
    authentication->set_iterations(iterations);
    authentication->set_salt(salt.data(), salt.size());
    authentication->set_hmac(hmac.data(), hmac.size());

    Vault vault;
    vault.set_allocated_authentication(authentication);
    auto store = vault.add_store();
    store->set_key(key);
    store->set_contents(encrypted.data(), encrypted.size());

    fstream file(path, ios::out | ios::binary | ios::trunc);
    if (!vault.SerializeToOstream(&file)) {
        throw runtime_error("vault data serialization failed");
    }

    return encode_token(*authentication, aes_key, aes_iv, mac_key);
}

token_t vault::create(const string &path, const string &password)
{
    blob_t salt = rand(SALT_SIZE);
    const int secret_size = AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE;
    int iterations = estimate_iterations(password, salt, secret_size);
    blob_t secret = generate_secret(password, salt, iterations, secret_size);

    blob_t aes_key(secret.cbegin(), secret.cbegin() + AES_KEY_SIZE);
    blob_t aes_iv(secret.cbegin() + AES_KEY_SIZE, secret.cbegin() + AES_KEY_SIZE + IV_SIZE);
    blob_t mac_key(secret.cbegin() + AES_KEY_SIZE + IV_SIZE, secret.cend());

    blob_t tmp;
    tmp.insert(tmp.end(), secret.begin(), secret.end());
    blob_t hmac = calc_hmac(tmp, HMAC_KEY_SIZE);

    auto authentication = new Authentication;
    authentication->set_iterations(iterations);
    authentication->set_salt(salt.data(), salt.size());
    authentication->set_hmac(hmac.data(), hmac.size());

    Vault vault;
    vault.set_allocated_authentication(authentication);

    fstream file(path, ios::out | ios::binary | ios::trunc);
    if (!vault.SerializeToOstream(&file)) {
        throw runtime_error("vault data serialization failed");
    }

    return encode_token(*authentication, aes_key, aes_iv, mac_key);
}

userdata_t vault::read(const string &path, const string &password,  const string &key, token_t *token)
{
    Vault vault;

    fstream file(path, ios::in | ios::binary);
    vault.ParseFromIstream(&file);

    blob_t salt(make_blob(vault.authentication().salt()));
    blob_t hmac(make_blob(vault.authentication().hmac()));
    const int secret_size = AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE;
    blob_t secret = generate_secret(password, salt, vault.authentication().iterations(), secret_size);

    blob_t tmp;
    Store * foundStore = nullptr;
    for (auto i = 0; i < vault.store_size(); i++) {
        auto store = vault.mutable_store(i);
        blob_t contents = make_blob(store->contents());
        tmp.insert(tmp.end(), contents.begin(), contents.end());
        if (store->key() == key) {
            foundStore = store;
        }
    }

    tmp.insert(tmp.end(), secret.begin(), secret.end());
    blob_t mac = calc_hmac(tmp, HMAC_KEY_SIZE);
    if (mac != hmac) {
        throw runtime_error("wrong password");
    }

    if (nullptr == foundStore) {
        throw runtime_error("key not found");
    }

    blob_t aes_key(secret.begin(), secret.begin() + AES_KEY_SIZE);
    blob_t aes_iv(secret.begin() + AES_KEY_SIZE, secret.begin() + AES_KEY_SIZE + IV_SIZE);
    blob_t mac_key(secret.begin() + AES_KEY_SIZE + IV_SIZE, secret.end());

    if (token) {
        *token = encode_token(vault.authentication(), aes_key, aes_iv, mac_key);
    }

    return decrypt(make_blob(foundStore->contents()), aes_key, aes_iv);
}

userdata_t vault::read(const string &path, const token_t &token, const std::string &key)
{

    Vault vault;
    fstream file(path, ios::in | ios::binary);
    if (!vault.ParseFromIstream(&file)) {
        throw runtime_error("failed to decode vault file");
    }

    Authentication _authentication;
    blob_t aes_key;
    blob_t aes_iv;
    blob_t mac_key;
    decode_token(token, _authentication, aes_key, aes_iv, mac_key);

    blob_t hmac(make_blob(vault.authentication().hmac()));
    blob_t tmp;
    Store * foundStore = nullptr;
    for (int i = 0; i < vault.store_size(); i++) {
        auto store = vault.mutable_store(i);
        blob_t contents = make_blob(store->contents());
        tmp.insert(tmp.end(), contents.begin(), contents.end());
        if (store->key() == key) {
            foundStore = store;
        }
    }

    if (nullptr == foundStore) {
        throw runtime_error("key not found");
    }

    tmp.insert(tmp.end(), aes_key.begin(), aes_key.end());
    tmp.insert(tmp.end(), aes_iv.begin(), aes_iv.end());
    tmp.insert(tmp.end(), mac_key.begin(), mac_key.end());
    blob_t mac = calc_hmac(tmp, HMAC_KEY_SIZE);

    if (!std::equal(mac.begin(), mac.end(), hmac.begin())) {
        throw runtime_error("wrong password");
    }

    blob_t contents(make_blob(foundStore->contents()));

    return decrypt(contents, aes_key, aes_iv);
}

void vault::update(const string &path, const token_t &token, const userdata_t &userdata, const std::string & key)
{
    Authentication _authentication;
    blob_t aes_key;
    blob_t aes_iv;
    blob_t mac_key;
    decode_token(token, _authentication, aes_key, aes_iv, mac_key);
    blob_t encrypted = encrypt(userdata, aes_key, aes_iv);

    Vault vault;
    fstream ifile(path, ios::in | ios::binary);
    if (!vault.ParseFromIstream(&ifile)) {
        throw runtime_error("failed to decode vault file");
    }

    Store * foundStore = nullptr;
    for (int i = 0; i < vault.store_size(); i++) {
        auto store = vault.mutable_store(i);
        if (store->key() == key) {
            foundStore = store;
        }
    }

    if (nullptr == foundStore) {
        throw runtime_error("key not found");
    }

    foundStore->set_contents(encrypted.data(), encrypted.size());

    blob_t tmp;
    for (int i = 0; i < vault.store_size(); i++) {
        auto store = vault.mutable_store(i);
        blob_t contents = make_blob(store->contents());
        tmp.insert(tmp.end(), contents.begin(), contents.end());
    }

    tmp.insert(tmp.end(), aes_key.begin(), aes_key.end());
    tmp.insert(tmp.end(), aes_iv.begin(), aes_iv.end());
    tmp.insert(tmp.end(), mac_key.begin(), mac_key.end());
    blob_t newMac = calc_hmac(tmp, HMAC_KEY_SIZE);

    auto authentication = vault.mutable_authentication();
    authentication->set_hmac(newMac.data(), newMac.size());

    fstream ofile(path, ios::out | ios::binary | ios::trunc);
    if (!vault.SerializeToOstream(&ofile)) {
        throw runtime_error("failed to encode vault file");
    }
}

void vault::add(const string &path, const token_t &token, const userdata_t &userdata, const std::string & key)
{
    Authentication _authentication;
    blob_t aes_key;
    blob_t aes_iv;
    blob_t mac_key;
    decode_token(token, _authentication, aes_key, aes_iv, mac_key);
    blob_t encrypted = encrypt(userdata, aes_key, aes_iv);

    Vault vault;
    fstream ifile(path, ios::in | ios::binary);
    if (!vault.ParseFromIstream(&ifile)) {
        throw runtime_error("failed to decode vault file");
    }

    for (int i = 0; i < vault.store_size(); i++) {
        auto store = vault.mutable_store(i);
        if (store->key() == key) {
            throw runtime_error("key not found");
        }
    }

    auto store = vault.add_store();
    store->set_key(key);
    store->set_contents(encrypted.data(), encrypted.size());

    blob_t tmp;
    for (int i = 0; i < vault.store_size(); i++) {
        auto store = vault.mutable_store(i);
        blob_t contents = make_blob(store->contents());
        tmp.insert(tmp.end(), contents.begin(), contents.end());
    }

    tmp.insert(tmp.end(), aes_key.begin(), aes_key.end());
    tmp.insert(tmp.end(), aes_iv.begin(), aes_iv.end());
    tmp.insert(tmp.end(), mac_key.begin(), mac_key.end());
    blob_t newMac = calc_hmac(tmp, HMAC_KEY_SIZE);

    auto authentication = vault.mutable_authentication();
    authentication->set_hmac(newMac.data(), newMac.size());

    fstream ofile(path, ios::out | ios::binary | ios::trunc);
    if (!vault.SerializeToOstream(&ofile)) {
        throw runtime_error("failed to encode vault file");
    }
}
