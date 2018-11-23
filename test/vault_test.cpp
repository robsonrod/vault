#include <vault.h>
#include <gtest/gtest.h>
#include <fstream>
#include <algorithm>

static std::vector<uint8_t> StringToByteArray(const std::string &str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

TEST(VaultTest, BasicCreateReadWithoutKeyTest) {
    auto token = vault::create("vault.bin", "password");
    EXPECT_FALSE(token.empty());

    EXPECT_THROW(vault::read("vault.bin", token, "test"), std::runtime_error);

    EXPECT_FALSE(token.empty());
}

TEST(VaultTest, BasicCreateUpdateReadTest) {
    std::vector<uint8_t> contents1(StringToByteArray("initial contents"));
    std::vector<uint8_t> contents2(StringToByteArray("updated"));

    auto token = vault::create("vault.bin", "password", "test", contents1);
    EXPECT_FALSE(token.empty());

    vault::update("vault.bin", token, contents2, "test");
    auto read_contents = vault::read("vault.bin", token, "test");
    auto read_contents2 = vault::read("vault.bin", "password", "test");

    EXPECT_EQ(read_contents, contents2);
    EXPECT_FALSE(token.empty());
}

TEST(VaultTest, ReadWithPasswordTest) {
    std::vector<uint8_t> contents(StringToByteArray("initial contents"));

    auto token = vault::create("vault.bin", "password", "test", contents);
    EXPECT_FALSE(token.empty());

    vault::token_t read_token;
    auto read_contents = vault::read("vault.bin", "password", "test", &read_token);

    EXPECT_EQ(read_contents, contents);
    EXPECT_FALSE(read_token.empty());
}

TEST(VaultTest, ReadWithPasswordAddTest) {
    std::vector<uint8_t> contents(StringToByteArray("initial contents"));
    std::vector<uint8_t> contents2(StringToByteArray("updated"));

    auto token = vault::create("vault.bin", "password", "test", contents);
    EXPECT_FALSE(token.empty());

    vault::token_t read_token;
    auto read_contents = vault::read("vault.bin", "password", "test", &read_token);

    EXPECT_EQ(read_contents, contents);
    EXPECT_FALSE(read_token.empty());

    vault::add("vault.bin", token, contents2, "test2");
    auto read_contents2 = vault::read("vault.bin", "password", "test2");
    EXPECT_EQ(read_contents2, contents2);
}

TEST(VaultTest, ReadWithWrongPasswordTest) {
    std::vector<uint8_t> contents(StringToByteArray("initial contents"));

    auto token = vault::create("vault.bin", "password", "key", contents);
    EXPECT_FALSE(token.empty());

    EXPECT_THROW(vault::read("vault.bin", "wrong password", "test"), std::runtime_error);
}

TEST(VaultTest, ReadWithWrongTokenTest) {
    std::vector<uint8_t> contents(StringToByteArray("initial contents"));

    auto token = vault::create("vault.bin", "password", "test", contents);
    EXPECT_FALSE(token.empty());

    std::reverse(std::begin(token), std::end(token));
    EXPECT_THROW(vault::read("vault.bin", token, "test"), std::runtime_error);
}
