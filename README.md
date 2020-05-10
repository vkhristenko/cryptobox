# Simple Cryptobox - Simple HSM like functionality 

## Requirements
- `cmake` 3.8 and above

## Usage
Key creation
```
./cryptobox --create N
--- Cryptobox --- 
Key Handle <32bit> created
Key Handle <32bit> created
...
Key Handle <32bit> created
```

Signing a msg
```
./cryptobox --sign msg --handle <32bit>
SignedMsg: hex-encoded blob
```

Verifying a signature
```
./cryptobox --verify <hex-encoded blob> --handle <32bit>
Rejected/Accepted
```
