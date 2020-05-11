#ifndef cryptobox_core_HSM_hpp
#define cryptobox_core_HSM_hpp

#include <string>
#include <optional>

#include "cryptobox/core/Common.hpp"

namespace cryptobox {

class HSM {
public:
    // status for the verification of the signature
    enum Status {
        Accepted,
        Rejected
    };

    HSM(std::string const&);
    ~HSM();

    // create a new entry
    std::optional<HandleT> Create();

    // sign
    std::optional<Buffer> Sign(HandleT, Buffer const&);

    // verify
    std::optional<std::pair<Status, Buffer>> Verify(HandleT, Buffer const&);

private:
    HandleEntryMap entries_;
    std::string storagePath_;
};

}

#endif // cryptobox_core_HSM_hpp
