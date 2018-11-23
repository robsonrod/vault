#ifndef VAULT_H
#define VAULT_H

#include <string>
#include <vector>
#include <ostream>

namespace vault {

    // marker interfaces
    typedef std::vector<uint8_t> token_t;
    typedef std::vector<uint8_t> userdata_t;

    // Creates a new password protected file from userdata.
    // Returns token that can be used to authorize read() or update() without providing a password.
    // Note: an existing file will be overwritten and truncated.
    token_t create(const std::string &path, const std::string &password, const std::string &key, const userdata_t &userdata);

    token_t create(const std::string &path, const std::string &password);

    // Reads and decrypts the encrypted file protected with the password.
    // If a wrong password is specified, this throws runtime_error exception.
    userdata_t read(const std::string &path, const std::string &password, const std::string &key, token_t *token = nullptr);

    // Reads and decrypts the encrypted file using the token instead of a password.
    userdata_t read(const std::string &path, const token_t &token, const std::string & key);

    // Updates the encrypted file contents using the token instead of a password.
    void update(const std::string &path, const token_t &token, const userdata_t &userdata, const std::string & key);

    // Updates the encrypted file contents using the token instead of a password.
    void add(const std::string &path, const token_t &token, const userdata_t &userdata, const std::string & key);

}

#endif // VAULT_H
