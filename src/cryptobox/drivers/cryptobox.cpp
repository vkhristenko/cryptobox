#include <iostream>

#include <boost/program_options.hpp>

#include "sodium.h"

#include "cryptobox/core/HSM.hpp"

namespace po = boost::program_options;
namespace crb = cryptobox;

void printHelp(std::ostream& out, po::options_description const& desc) {
    out << "--- Simple Cryptobox ---\n";
    out << desc << "\n";
}

// something very simple
const std::string defaultStorageLocation = "default.crb";

void createKeys(std::ostream& out, int nKeys) {
    cryptobox::HSM hsm{defaultStorageLocation};
    std::vector<std::optional<uint32_t>> ids(nKeys);

    for (auto& h : ids)
        h = hsm.Create();

    for (auto const& h : ids)
        h ? out << "Key Handle " << h.value() << " created\n" : std::cout << "Invalid Key Handle";
}

void signMessage(std::ostream& out, uint32_t const handle, std::string const& msg) {
    cryptobox::HSM hsm{defaultStorageLocation};

    // for the original message it is a simple copy
    std::vector<unsigned char> msgV(msg.size());
    for (int i=0; i<msg.size(); i++)
        msgV[i] = msg[i];
    // signing
    if (auto signedMsg = hsm.Sign(handle, msgV); signedMsg.has_value()) {
        // we output hex-formatted binary blob for the signature
        std::vector<char> hex(signedMsg.value().size()*2+1);
        sodium_bin2hex(hex.data(), hex.size(),
            signedMsg.value().data(), signedMsg.value().size());
        for (auto const c : hex)
            out << c;
        out << '\n';
    } else {
        // ERROR
        out << "Invalid handle provided...\n";
    }
}

void verifySignature(std::ostream& out, 
        uint32_t const handle, std::string const& signedMsg) {
    cryptobox::HSM hsm{defaultStorageLocation};

    // decode hex to bin
    std::vector<unsigned char> bin(signedMsg.size());
    size_t bin_len;
    sodium_hex2bin(bin.data(), bin.size(),
        signedMsg.data(), signedMsg.size(),
        NULL, &bin_len, NULL);
    assert(bin_len>0 && "Hex to Bin length greater than 0");
    bin.resize(bin_len);
    for (auto const c : bin)
        printf("%c", c);
    printf("\n");

    if (auto result = hsm.Verify(handle, bin); result.has_value()) {
        if (auto status = result.value().first; status == crb::HSM::Rejected)
            out << "Verification: Rejected\n";
        else
            out << "Verification: Accepted\n";
    } else {
        // ERROR
        out << "Invalid handle provided...\n";
    }
}

int main(int argc, char** argv) {
    
    // Declare the supported options.
    po::options_description desc("Allowed options:");
    desc.add_options()
        ("help", "produce help message")
        ("create", po::value<int>(), "create N keys")
        ("sign", po::value<std::string>(), "message to sign")
        ("verify", po::value<std::string>(), "signed msg to verify")
        ("handle", po::value<uint32_t>(), "handle id")
    ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    // help checked first
    if (vm.count("help")) {
        printHelp(std::cout, desc);
        return 0;
    }

    // keys creation
    if (vm.count("create")) {
        auto nKeysToCreate = vm["create"].as<int>();
        createKeys(std::cout, nKeysToCreate);
        // TODO
        return 0;
    }

    // signing process
    if (vm.count("sign")) {
        auto msg = vm["sign"].as<std::string>();
        if (vm.count("handle")) {
            auto handle = vm["handle"].as<uint32_t>();
            signMessage(std::cout, handle, msg);
            return 0;
        } else {
            std::cout << "No Key Handle/Id was provided to sign the msg... \n";
            return 0;
        }
    }

    if (vm.count("verify")) {
        auto signedMsg = vm["verify"].as<std::string>();
        if (vm.count("handle")) {
            auto handle = vm["handle"].as<uint32_t>();
            std::cout << "will verify: " << signedMsg << " with handle " << handle
                << "\n";
            verifySignature(std::cout, handle, signedMsg);
            return 0;
        } else {
            std::cout << "No Key Handle/Id was provided to sign the msg... \n";
            return 0;
        }
    }

    std::cout << "None of the known options were provided...\n\n";
    printHelp(std::cout, desc);
    return 0;
}
