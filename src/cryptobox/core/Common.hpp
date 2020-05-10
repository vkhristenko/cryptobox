#ifndef cryptobox_core_Common_hpp
#define cryptobox_core_Common_hpp

#include <vector>
#include <unordered_map>
#include <tuple>

namespace cryptobox {

using Buffer = std::vector<unsigned char>;
using HandleT = uint32_t;
using EntryT = std::tuple<std::vector<unsigned char>, std::vector<unsigned char>>;
using HandleEntryMap = std::unordered_map<HandleT, EntryT>;

}

#endif // cryptobox_core_Common_hpp
