#include <iostream>

#include "cryptobox/core/HSM.hpp"

using namespace cryptobox;

void print(std::vector<unsigned char> const& v) {
    for (auto const c : v)
        printf("%c", c);
    printf("\n");
}

int main() {
    // simple test for the very basic functionality: create/sign/verify
    auto hsm = std::make_shared<cryptobox::HSM>();

    // create
    auto handle = hsm->Create();
    assert(handle.has_value() && "Assert Valid Handle");

    // sign
    std::vector<unsigned char> msg = {'t', 'e', 'x', 't'};
    auto signedMsg = hsm->Sign(handle.value(), msg);
    assert(signedMsg.has_value() && "Assert Valid Signed Msg");

    // verify
    auto status = hsm->Verify(handle.value(), signedMsg.value());
    assert(status.has_value() && "Assert Valid Status");
    auto const& statusval = status.value();
    assert(statusval.first==HSM::Accepted && "Assert Status Valid == Accepted");

    // check the original msg and extracted from signedMsg match
    assert(statusval.second.size() == msg.size() && "Assert Original Msg size == Verified");
    for (int i=0; i<msg.size(); i++)
        assert(status.value().second[i] == msg[i] && "Assert Original msg == Verified msg");

    printf("all tests passed!\n");

    return 0;
}
