#include "cryptobox/core/Storage.hpp"

#include <boost/filesystem.hpp>

#include "sodium.h"

namespace fs = boost::filesystem;

namespace cryptobox { namespace io {

template<typename Stream>
struct FileGuard {
    FileGuard(std::string const& pathName)
        : f{pathName}
    {}

    ~FileGuard() { f.close(); }

    Stream f;
};

void dump(std::string const& storagePath, HandleEntryMap const& keys) {
    FileGuard<std::ofstream> g{storagePath};

    for (auto const& p : keys) {
        g.f << std::to_string(p.first) << std::endl;
        g.f << convert_bin2hex(std::get<0>(p.second)) << std::endl;
        g.f << convert_bin2hex(std::get<1>(p.second)) << std::endl;
    }
}

HandleEntryMap retrieve(std::string const& storagePath) {
    HandleEntryMap m;

    // check if the file already exists
    if (fs::path p{storagePath}; fs::exists(p)) {
        std::string line;

        // if there were problems, leave
        if (FileGuard<std::ifstream> g{storagePath}; g.f.is_open()) {
            // parse
            int ii = 0;
            uint32_t handle;
            std::vector<unsigned char> pubKey, privKey;
            while (std::getline(g.f, line)) {
                if (ii%3==0) handle = std::stoul(line);
                if (ii%3==1) pubKey = convert_hex2bin(line);
                if (ii%3==2) {
                    // last item for this entry
                    privKey = convert_hex2bin(line);

                    // add the entry
                    m[handle] = {pubKey, privKey};
                }
                ii++;
            }
        }
    }

    return m;
}

std::vector<unsigned char> convert_hex2bin(std::string const& s) {
    std::vector<unsigned char> bin(s.size());
    size_t bin_len;
    sodium_hex2bin(bin.data(), bin.size(), s.data(), s.size(), NULL, 
        &bin_len, NULL);
    assert(bin_len>0 && "Hex to Bin length greater than 0");
    bin.resize(bin_len);
    return bin;
}

std::string convert_bin2hex(std::vector<unsigned char> const& bin) {
    std::string hex(bin.size()*2+1, 'x');
    sodium_bin2hex(hex.data(), hex.size(),
        bin.data(), bin.size());
    return hex;
}

}}
