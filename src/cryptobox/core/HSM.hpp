#ifndef cryptobox_core_HSM_hpp
#define cryptobox_core_HSM_hpp

#include <vector>
#include <string>
#include <unordered_map>
#include <tuple>
#include <optional>

namespace cryptobox {

// TODO: remove in the future
using Buffer = std::vector<unsigned char>;

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
    std::optional<Buffer> Sign(HandleT, Buffer const&);

    // verify
    std::optional<std::pair<Status, Buffer>> Verify(HandleT, Buffer const&);

private:
    HandleEntryMap entries_;
};

}

#endif // cryptobox_core_HSM_hpp
