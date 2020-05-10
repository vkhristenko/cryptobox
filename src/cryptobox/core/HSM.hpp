#ifndef cryptobox_core_HSM_hpp
#define cryptobox_core_HSM_hpp

#include <vector>
#include <string>
#include <unordered_map>
#include <tuple>
#include <optional>

namespace cryptobox {

// TODO: remove in the future
using Message = std::string;
using SignedMessage = std::string;

class HSM {
public:
    // TODO: static_assert()

    // status for the verification of the signature
    enum Status {
        Accepted,
        Rejected
    };

    using HandleT = uint32_t;
    using EntryT = std::tuple<std::vector<unsigned char>, std::vector<unsigned char>>;
    using HandleEntryMap = std::unordered_map<HandleT, EntryT>;

    HSM();
    ~HSM();

    // create a new entry
    std::optional<HandleT> Create();

    // sign
    std::optional<SignedMessage> Sign(HandleT, Message);

    // verify
    std::optional<Status> Verify(HandleT, SignedMessage);

private:
    HandleEntryMap entries_;
};

}

#endif // cryptobox_core_HSM_hpp
