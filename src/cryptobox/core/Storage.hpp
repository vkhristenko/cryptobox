#ifndef cryptobox_core_Storage_hpp
#define cryptobox_core_Storage_hpp

#include "cryptobox/core/Common.hpp"

namespace cryptobox { namespace io {

void dump(std::string const&, HandleEntryMap const&);

HandleEntryMap retrieve(std::string const&);

std::vector<unsigned char> convert_hex2bin(std::string const&);

std::string convert_bin2hex(std::vector<unsigned char> const&);

}}

#endif // cryptobox_core_Storage_hpp
