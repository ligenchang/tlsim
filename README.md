# Educational TLS 1.2 Implementation

A complete educational implementation of TLS 1.2 handshake with RSA key exchange, demonstrating the core cryptographic operations and message flows.

## What's Implemented

### Complete TLS 1.2 Handshake
✅ **ClientHello** - Cipher suite negotiation with SNI extension  
✅ **ServerHello** - Parse server's selected parameters  
✅ **Certificate** - Parse and verify certificate chain  
✅ **ClientKeyExchange** - RSA key exchange with pre-master secret  
✅ **ChangeCipherSpec** - Signal transition to encrypted communication  
✅ **Finished** - Encrypted handshake verification (both directions)  

### Cryptographic Operations
✅ **TLS PRF** - Pseudorandom function using HMAC-SHA256  
✅ **Key Derivation** - Master secret and session key generation  
✅ **AES-128-CBC** - Symmetric encryption with explicit IVs  
✅ **HMAC-SHA1** - Message authentication codes  
✅ **PKCS#7 Padding** - Proper block cipher padding  
✅ **RSA Encryption** - Pre-master secret protection  

### Security Features
✅ **Certificate Chain Validation** - Verify against system trust store  
✅ **Hostname Verification** - Check CN and SAN fields  
✅ **Sequence Numbers** - Replay attack prevention  
✅ **MAC Verification** - Ensure message integrity  
✅ **Finished Message** - Mutual handshake verification  

## Usage

```bash
# Test with a server that supports RSA key exchange
python main.py <hostname>

# Examples
python main.py badssl.com        # BadSSL test server
python main.py example.com       # Try various hosts
```

## Current Limitations

### Only RSA Key Exchange
Modern servers (Google, Amazon, etc.) require **ECDHE** for Perfect Forward Secrecy. This implementation demonstrates RSA key exchange only. When connecting to such servers, you'll see an educational message explaining ECDHE.

### TLS 1.2 Only
TLS 1.3 is now standard, but TLS 1.2 is better for educational purposes as it clearly shows each handshake message.

### No AEAD Ciphers
Only CBC mode is implemented. Modern TLS uses AEAD ciphers like GCM and ChaCha20-Poly1305.

## Educational Value

This implementation shows:

1. **How TLS Handshake Works** - Complete message flow from ClientHello to Finished
2. **Key Derivation** - How pre-master secret → master secret → session keys
3. **Authenticated Encryption** - MAC-then-Encrypt pattern (TLS 1.2)
4. **Certificate Validation** - Full chain verification against trust store
5. **Protocol Details** - TLS record format, handshake messages, etc.

## Example Output

```
============================================================
EDUCATIONAL TLS 1.2 CLIENT
============================================================
Target: example.com:443
Protocol: TLS 1.2
Cipher Suites Offered (RSA key exchange only):
  - TLS_RSA_WITH_AES_128_CBC_SHA
  - TLS_RSA_WITH_AES_256_CBC_SHA
============================================================

Step 1: Establishing TCP connection...
[OK] Connected to example.com:443

Step 2: Sending ClientHello...
[OK] Sent ClientHello (114 bytes)

Step 3: Receiving server handshake messages...
[OK] Received 1234 bytes from server

Step 4: Parsing TLS records...

============================================================
SERVER HELLO
============================================================
TLS Version: 0303
Cipher Suite: 002f (TLS_RSA_WITH_AES_128_CBC_SHA)

============================================================
SERVER CERTIFICATE
============================================================
[Certificate validation details...]

============================================================
CLIENT KEY EXCHANGE
============================================================
Pre-Master Secret: 0303...
Encrypted with server's RSA public key

============================================================
KEY DERIVATION
============================================================
Master Secret: ...
Session Keys: ...

============================================================
FINISHED MESSAGE (ENCRYPTED)
============================================================
[Encrypted handshake verification...]

🎉 HANDSHAKE SUCCESSFULLY COMPLETED!
```

## Implementation Notes

### Key Derivation (RFC 5246)
```
master_secret = PRF(pre_master_secret, "master secret", 
                    client_random + server_random)[0..47]

key_block = PRF(master_secret, "key expansion",
                server_random + client_random)

Split key_block into:
  - client_write_MAC_key
  - server_write_MAC_key
  - client_write_key
  - server_write_key
```

### Explicit IVs (TLS 1.2)
Unlike TLS 1.0/1.1, TLS 1.2 with CBC uses explicit IVs:
- Each record has a random 16-byte IV prepended
- IVs are NOT derived from the key block
- This prevents the BEAST attack

### Finished Message
```
verify_data = PRF(master_secret, "client finished",
                  SHA256(all_handshake_messages))[0..11]
```

## For Production Use

**Never use this for production!** This is educational code only.

For production TLS:
- Use Python's `ssl` module (wraps OpenSSL)
- Use TLS 1.3 with ECDHE and AEAD ciphers
- Enable OCSP stapling and certificate transparency
- Implement proper timing attack prevention
- Use constant-time cryptographic operations

## Dependencies

```bash
pip install cryptography certifi
```

## References

- [RFC 5246](https://tools.ietf.org/html/rfc5246) - TLS 1.2 Specification
- [RFC 2246](https://tools.ietf.org/html/rfc2246) - TLS 1.0 (historical context)
- [RFC 8446](https://tools.ietf.org/html/rfc8446) - TLS 1.3 (modern standard)

## License

Educational use only. See LICENSE file.
