#include <fstream>
#include <iostream>

#include "sodium.h"

#include "cryptobox/core/HSM.hpp"
#include "cryptobox/core/Storage.hpp"

namespace cryptobox {

HSM::HSM(std::string const& storagePath) 
    : storagePath_{storagePath}
{
    // bring up the key store
    entries_ = std::move(io::retrieve(storagePath_));
}

HSM::~HSM() {
    // dump the key store
    io::dump(storagePath_, entries_);
}

std::optional<HandleT> HSM::Create() {
    // generate a handle
    auto handle = randombytes_random();

    // fill in the public/private key
    std::vector<unsigned char> pubKey(crypto_sign_PUBLICKEYBYTES);
    std::vector<unsigned char> privKey(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(pubKey.data(), privKey.data());

    // add an etry
    entries_[handle] = {pubKey, privKey};

    return handle;
}

std::optional<Buffer> HSM::Sign(HandleT handle, Buffer const& msg) {
    // signed msg buffer
    std::vector<unsigned char> signedMsg(crypto_sign_BYTES + msg.size());
    
    // get the private key
    if (auto iter = entries_.find(handle); iter != entries_.end()) {
        auto const& privKey = std::get<1>(iter->second);

        // sign
        unsigned long long signedMsgLen;
        crypto_sign(signedMsg.data(), &signedMsgLen,
            msg.data(), msg.size(), privKey.data());
        assert(signedMsgLen>0 && "Assert Signed Msg Length is greater than 0");
        signedMsg.resize(signedMsgLen);

        return signedMsg;
    } 

    return {};
}

std::optional<std::pair<HSM::Status, Buffer>> HSM::Verify(
        HandleT handle, Buffer const& signedMsg) {
    // reserve at least the size of the signed msg
    std::vector<unsigned char> msg(signedMsg.size());

    if (auto iter = entries_.find(handle); iter != entries_.end()) {
        unsigned long long msgLen;
        Status status = Accepted;
        auto const& pubKey = std::get<0>(iter->second);
        if (crypto_sign_open(msg.data(), &msgLen, 
            signedMsg.data(), signedMsg.size(), pubKey.data()) != 0) {
            status = Rejected;
            return std::pair{status, msg};
        }
        assert(msgLen > 0 && "Assert Msg Length After Verification is greated than 0");
        msg.resize(msgLen);
        return std::pair{status, msg};
    }

    return {};
}

}
