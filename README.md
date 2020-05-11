# Simple Cryptobox - Simple HSM like functionality 
Employing `libsodium` for public/private key generation, signature and verification procedure. In particular, `libsodium` supports `curve25519` only with EdDSA for signature generation/authenticity verification.

## Requirements
- `cmake` 3.8 and above
- `libsodium`
- `boost`

## Installation
Assuming
- `libsodium` is installed in `$SODIUM_INSTALL`
```
git clone https://github.com/vkhristenko/cryptobox && cd cryptobox
mkdir build && cd build
cmake -DDCMAKE_PREFIX_PATH=$SODIUM_INSTALL ../
make -j N
```

the main executable is located in `build/src/cryptobox/drivers`. there is a rule for `install` target, but not used here for simplicity.

## Usage
Key creation
```
./cryptobox --create 10
Key Handle 4129717526 created
Key Handle 1058730520 created
Key Handle 1584837623 created
Key Handle 2946837651 created
Key Handle 3055165083 created
Key Handle 3261598646 created
Key Handle 1943014097 created
Key Handle 2096332338 created
Key Handle 3059205084 created
Key Handle 3185867906 created
```

Signing a msg
- Input comes in in the form of text. Below is an example for 32byte string
- Output is hex-encoded binary signed message.
```
./cryptobox --sign aaaaaaaabbbbbbbbccccccccdddddddd --handle 4129717526
5fc21f7b503944e1ae759c2805348af22a75c6ddfe82cd99a39ba02cd80806ce67255dff66489fa39046ecc1ec28519e9ca5c74c2d5edf062439f309b11bdd016161616161616161626262626262626263636363636363636464646464646464
```

Verifying a signature
- Input: signed message with handle
- Output rejection/acceptance
```
./cryptobox --verify 5fc21f7b503944e1ae759c2805348af22a75c6ddfe82cd99a39ba02cd80806ce67255dff66489fa39046ecc1ec28519e9ca5c74c2d5edf062439f309b11bdd016161616161616161626262626262626263636363636363636464646464646464 --handle 4129717526
Verification: Accepted
```

change a single char:
```
./cryptobox --verify 5fc21f7b503044e1ae759c2805348af22a75c6ddfe82cd99a39ba02cd80806ce67255dff66489fa39046ecc1ec28519e9ca5c74c2d5edf062439f309b11bdd016161616161616161626262626262626263636363636363636464646464646464 --handle 4129717526
Verification: Rejected
```
