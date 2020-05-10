#include <iostream>

#include "cryptobox/core/HSM.hpp"

using namespace cryptobox;

int main() {
    // simple test for the very basic functionality: create/sign/verify
    auto hsm = std::make_shared<cryptobox::HSM>();

    // create
    auto handle = hsm->Create();
    assert(handle.has_value() && "Assert Valid Handle");

    // sign
    std::string msg = "Text";
    auto signedMsg = hsm->Sign(handle.value(), msg);
    assert(signedMsg.has_value() && "Assert Valid Signed Msg");

    // verify
    auto status = hsm->Verify(handle.value(), signedMsg.value());
    assert(status.has_value() && "Assert Valid Status");
    assert(status.value()==HSM::Rejected && "Assert Status Valud == Rejected");

    return 0;
}
