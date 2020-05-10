#include "cryptobox/core/HSM.hpp"

#include <fstream>

namespace cryptobox {

HSM::HSM() {}

HSM::~HSM() {
}

std::optional<HSM::HandleT> HSM::Create() {
    static HandleT count = 0;
    entries_[count++] = {};

    return count;
}

std::optional<SignedMessage> HSM::Sign(HandleT, Message) {
    return {};
}

std::optional<HSM::Status> HSM::Verify(HandleT, SignedMessage) {
    return std::nullopt;
}

}
