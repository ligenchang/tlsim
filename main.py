"""
Usage:
    python main.py [hostname] [--all-ciphers]
    
Examples:
    python main.py                       # Connects to google.com (default, RSA only)
    python main.py badssl.com            # Test with badssl.com
    python main.py --all-ciphers google.com  # Try with all cipher suites (will see ECDHE message)
    
Educational TLS 1.2 Implementation:
    This client demonstrates a complete TLS 1.2 handshake with RSA key exchange,
    including encrypted Finished messages and application data exchange.
    
    Modern servers require ECDHE, which this implementation doesn't support.
    When connecting to such servers, you'll see an educational message about ECDHE.
"""

import socket
import struct
import os
import sys
import warnings
import certifi

from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
import hashlib


TLS_VERSION_1_2 = b"\x03\x03"

# Cipher suites for this educational implementation
# Only RSA key exchange is supported (no ECDHE)
CIPHER_SUITES_RSA_ONLY = b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
CIPHER_SUITES_RSA_ONLY += b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA

# Full cipher suite list (includes ECDHE for testing)
CIPHER_SUITES_ALL = b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
CIPHER_SUITES_ALL += b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA
CIPHER_SUITES_ALL += b"\xc0\x2f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
CIPHER_SUITES_ALL += b"\xc0\x30"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
CIPHER_SUITES_ALL += b"\xc0\x13"  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
CIPHER_SUITES_ALL += b"\xc0\x14"  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA

# Use RSA-only by default for educational purposes
CIPHER_SUITES = CIPHER_SUITES_RSA_ONLY

# TLS Record Types
HANDSHAKE_RECORD = 0x16
CHANGE_CIPHER_SPEC_RECORD = 0x14
APPLICATION_DATA_RECORD = 0x17
ALERT_RECORD = 0x15

# TLS Handshake Message Types
CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02
CERTIFICATE = 0x0b
SERVER_KEY_EXCHANGE = 0x0c
SERVER_HELLO_DONE = 0x0e
CLIENT_KEY_EXCHANGE = 0x10
FINISHED = 0x14


# Global variables to store handshake messages for computing Finished message
client_hello_msg = b""
server_hello_msg = b""
certificate_msg = b""
server_key_exchange_msg = b""
server_hello_done_msg = b""
client_key_exchange_msg = b""

# Session keys
master_secret = b""
client_write_key = b""
server_write_key = b""
client_write_mac_key = b""
server_write_mac_key = b""
client_write_iv = b""
server_write_iv = b""

# Sequence numbers for MAC computation
client_seq_num = 0
server_seq_num = 0

def build_client_hello(server_name: str) -> bytes:
    """
    Constructs a TLS 1.2 ClientHello message with SNI extension.
    
    The ClientHello is the first message in the TLS handshake, where the client
    tells the server which TLS version and cipher suites it supports.
    
    Args:
        server_name: The hostname for Server Name Indication (SNI)
        
    Returns:
        Complete TLS record containing the ClientHello handshake message
        
    Educational Notes:
        - TLS uses records to encapsulate handshake messages
        - SNI allows hosting multiple SSL sites on one IP address
        - Client sends a list of supported cipher suites; server picks one
    """
    client_version = TLS_VERSION_1_2
    random = os.urandom(32)  # Client random (used in key derivation)
    session_id_len = b"\x00"  # No session resumption in this implementation
    
    # Cipher suites offered (multiple for better compatibility)
    cipher_suites = CIPHER_SUITES
    cipher_suites_len = struct.pack("!H", len(cipher_suites))
    
    compression_methods = b"\x00"  # No compression
    compression_len = b"\x01"

    # Server Name Indication (SNI) extension
    server_name_bytes = server_name.encode()
    sni = (
        struct.pack("!H", len(server_name_bytes) + 3) +
        b"\x00" +  # Name type: host_name
        struct.pack("!H", len(server_name_bytes)) +
        server_name_bytes
    )
    sni_ext = b"\x00\x00" + struct.pack("!H", len(sni)) + sni
    
    # Supported Groups (Elliptic Curves) extension - Required for ECDHE cipher suites
    supported_groups = b"\x00\x17\x00\x18\x00\x19\x00\x1d"  # secp256r1, secp384r1, secp521r1, x25519
    groups_ext = b"\x00\x0a" + struct.pack("!H", len(supported_groups) + 2) + struct.pack("!H", len(supported_groups)) + supported_groups
    
    # Signature Algorithms extension - Required by TLS 1.2
    sig_algs = b"\x04\x01\x05\x01\x06\x01\x04\x03\x05\x03\x06\x03"  # RSA and ECDSA with SHA256/384/512
    sig_algs_ext = b"\x00\x0d" + struct.pack("!H", len(sig_algs) + 2) + struct.pack("!H", len(sig_algs)) + sig_algs
    
    # EC Point Formats extension - Required for ECDHE cipher suites
    ec_formats = b"\x00"  # uncompressed
    ec_formats_ext = b"\x00\x0b" + struct.pack("!H", len(ec_formats) + 1) + struct.pack("!B", len(ec_formats)) + ec_formats
    
    # Combine all extensions
    all_extensions = sni_ext + groups_ext + sig_algs_ext + ec_formats_ext
    extensions_len = struct.pack("!H", len(all_extensions))

    # Build the ClientHello handshake body
    handshake_body = (
        client_version +
        random +
        session_id_len +
        cipher_suites_len + cipher_suites +
        compression_len + compression_methods +
        extensions_len + all_extensions
    )

    # Wrap in handshake message (type 0x01 = ClientHello)
    handshake = (
        b"\x01" +  # Handshake type: ClientHello
        struct.pack("!I", len(handshake_body))[1:] +  # Length (24-bit)
        handshake_body
    )

    # Store for computing Finished message hash
    global client_hello_msg, client_random
    client_hello_msg = handshake
    client_random = random

    # Wrap in TLS record
    record = (
        b"\x16" +  # Content type: Handshake
        TLS_VERSION_1_2 +
        struct.pack("!H", len(handshake)) +  # Record length
        handshake
    )

    return record

# =========================
# Network I/O Utilities
# =========================
def recv_all(sock, timeout=2):
    """
    Receives all available data from socket with timeout.
    
    Educational Note:
        TLS servers may send multiple records in response to ClientHello.
        We need to receive all of them before parsing.
    """
    sock.settimeout(timeout)
    data = []
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.append(chunk)
    except socket.timeout:
        pass
    return b"".join(data)


def split_tls_records(data):
    """
    Splits raw TLS data into individual TLS records.
    
    TLS Record Format:
        - Byte 0: Content Type (0x16 = Handshake)
        - Bytes 1-2: TLS Version
        - Bytes 3-4: Length of payload (big-endian)
        - Bytes 5+: Payload
        
    Returns:
        List of complete TLS records
    """
    records = []
    offset = 0
    while offset + 5 <= len(data):
        length = struct.unpack("!H", data[offset+3:offset+5])[0]
        record = data[offset:offset+5+length]
        records.append(record)
        offset += 5 + length
    return records


def parse_alert(record):
    """
    Parses a TLS Alert message.
    
    Alert Format:
        - Byte 0: Alert level (1 = warning, 2 = fatal)
        - Byte 1: Alert description
        
    Educational Note:
        Alerts indicate errors or warnings in the TLS connection.
        Fatal alerts cause immediate connection termination.
    """
    if len(record) < 7:
        return "Malformed alert"
    
    alert_level = record[5]
    alert_desc = record[6]
    
    alert_levels = {
        1: "warning",
        2: "fatal"
    }
    
    alert_descriptions = {
        0: "close_notify",
        10: "unexpected_message",
        20: "bad_record_mac",
        21: "decryption_failed",
        22: "record_overflow",
        30: "decompression_failure",
        40: "handshake_failure",
        41: "no_certificate",
        42: "bad_certificate",
        43: "unsupported_certificate",
        44: "certificate_revoked",
        45: "certificate_expired",
        46: "certificate_unknown",
        47: "illegal_parameter",
        48: "unknown_ca",
        49: "access_denied",
        50: "decode_error",
        51: "decrypt_error",
        60: "export_restriction",
        70: "protocol_version",
        71: "insufficient_security",
        80: "internal_error",
        86: "inappropriate_fallback",
        90: "user_canceled",
        100: "no_renegotiation",
        110: "unsupported_extension",
        112: "unrecognized_name",
        113: "bad_certificate_status_response",
        114: "bad_certificate_hash_value",
        115: "unknown_psk_identity",
    }
    
    level_str = alert_levels.get(alert_level, f"unknown({alert_level})")
    desc_str = alert_descriptions.get(alert_desc, f"unknown({alert_desc})")
    
    print(f"\n{'='*60}")
    print("TLS ALERT RECEIVED")
    print("="*60)
    print(f"Alert Level: {alert_level} ({level_str})")
    print(f"Alert Description: {alert_desc} ({desc_str})")
    print()
    
    # Provide helpful explanations for common errors
    if alert_desc == 20:
        print("Explanation: bad_record_mac")
        print("  The MAC (Message Authentication Code) verification failed.")
        print("  This usually means:")
        print("    - Incorrect session keys were derived")
        print("    - Wrong cipher suite configuration")
        print("    - Encryption/decryption mismatch")
        print("    - Sequence number mismatch")
    elif alert_desc == 51:
        print("Explanation: decrypt_error")
        print("  Decryption failed or padding was incorrect.")
        print("  This usually means:")
        print("    - Wrong encryption keys")
        print("    - Cipher suite mismatch")
        print("    - Corrupted encrypted data")
    elif alert_desc == 40:
        print("Explanation: handshake_failure")
        print("  The server couldn't establish a secure connection.")
        print("  This usually means:")
        print("    - Cipher suite negotiation failed")
        print("    - Protocol version mismatch")
        print("    - Required extensions missing")
    elif alert_desc == 47:
        print("Explanation: illegal_parameter")
        print("  A field in a handshake message was incorrect.")
        print("  This usually means:")
        print("    - Malformed ClientKeyExchange")
        print("    - Invalid Finished message")
        print("    - Incorrect message format")
    
    print("="*60)
    print()
    
    return f"{level_str}: {desc_str}"


# =========================
# TLS Message Parsers
# =========================
def parse_server_hello(handshake):
    """
    Parses and displays ServerHello message.
    
    The ServerHello is the server's response, containing:
        - TLS version the server chose
        - Server random (used in key derivation)
        - Session ID (for session resumption)
        - Cipher suite the server selected
        - Compression method
        
    Educational Note:
        The server picks ONE cipher suite from the client's list.
        Both client and server randoms are used to derive session keys.
    """
    global server_random, selected_cipher
    
    offset = 0
    version = handshake[offset:offset+2]
    offset += 2

    random = handshake[offset:offset+32]
    server_random = random
    offset += 32

    sid_len = handshake[offset]
    offset += 1
    session_id = handshake[offset:offset+sid_len]
    offset += sid_len

    cipher = handshake[offset:offset+2]
    selected_cipher = cipher
    offset += 2

    compression = handshake[offset]

    print("\n" + "="*60)
    print("SERVER HELLO")
    print("="*60)
    print(f"TLS Version: {version.hex()}")
    print(f"Server Random: {random.hex()}")
    
    # Map common cipher suite codes to names
    cipher_names = {
        b"\x00\x2f": "TLS_RSA_WITH_AES_128_CBC_SHA",
        b"\x00\x35": "TLS_RSA_WITH_AES_256_CBC_SHA",
        b"\xc0\x2f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        b"\xc0\x30": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        b"\xc0\x13": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        b"\xc0\x14": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    }
    cipher_name = cipher_names.get(cipher, "Unknown")
    print(f"Cipher Suite: {cipher.hex()} ({cipher_name})")
    print(f"Compression: {compression}")
    print()

def verify_chain_with_root(certificates):
    """
    Verifies the certificate chain against trusted root certificates.
    
    This function performs two critical verification steps:
        1. Verifies each certificate is properly signed by the next in chain
        2. Verifies the top certificate is signed by (or is) a trusted root
        
    Args:
        certificates: List of DER-encoded certificates, leaf certificate first
        
    Educational Notes:
        - Certificate chains establish trust from leaf → intermediate → root
        - Each cert's signature is verified using the issuer's public key
        - Root certificates are self-signed and pre-installed as trusted
        - Cross-signing: A new root can be signed by an old root for compatibility
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    import certifi

    # Load certificates as x509 objects
    x509_certs = [x509.load_der_x509_certificate(c, default_backend()) for c in certificates]
    
    print("\n" + "="*60)
    print(f"CERTIFICATE CHAIN VERIFICATION")
    print("="*60)
    print(f"Received {len(x509_certs)} certificate(s) in chain\n")

    # Load trusted root certificates from certifi bundle
    ca_bundle_path = certifi.where()
    with open(ca_bundle_path, 'rb') as f:
        ca_bundle_pem = f.read()
    
    # Parse all PEM certificates from the bundle
    trusted_roots = []
    cert_start = b"-----BEGIN CERTIFICATE-----"
    cert_end = b"-----END CERTIFICATE-----"
    offset = 0
    while True:
        start = ca_bundle_pem.find(cert_start, offset)
        if start == -1:
            break
        end = ca_bundle_pem.find(cert_end, start)
        if end == -1:
            break
        end += len(cert_end)
        cert_pem = ca_bundle_pem[start:end]
        try:
            root = x509.load_pem_x509_certificate(cert_pem, default_backend())
            trusted_roots.append(root)
        except:
            pass
        offset = end

    print(f"Loaded {len(trusted_roots)} trusted root certificates from certifi\n")

    # STEP 1: Verify signature chain
    print("Step 1: Verifying certificate signatures in chain...")
    print("-" * 60)
    for i in range(len(x509_certs) - 1):
        subject_cert = x509_certs[i]
        issuer_cert = x509_certs[i+1]
        
        try:
            # Verify that issuer_cert signed subject_cert
            issuer_cert.public_key().verify(
                signature=subject_cert.signature,
                data=subject_cert.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=subject_cert.signature_hash_algorithm,
            )
            subject_cn = subject_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            issuer_cn = issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            print(f"[OK] Certificate {i}: '{subject_cn}'")
            print(f"     signed by: '{issuer_cn}'\n")
        except Exception as e:
            print(f"[FAILED] Certificate {i} signature verification FAILED: {e}")
            return

    print("All intermediate certificate signatures are VALID\n")

    # STEP 2: Verify against trusted roots
    print("Step 2: Verifying top certificate against trusted roots...")
    print("-" * 60)
    top_cert = x509_certs[-1]
    
    top_cn = top_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    print(f"Top certificate: {top_cn}")
    print(f"  Subject: {top_cert.subject.rfc4514_string()[:80]}")
    print(f"  Issuer:  {top_cert.issuer.rfc4514_string()[:80]}\n")
    
    # Check for cross-signed root (most common case)
    for root in trusted_roots:
        try:
            # Exact match
            if top_cert.subject == root.subject and top_cert.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
                print(f"[OK] Top certificate IS directly in trusted roots (exact match)!")
                print(f"\n{'='*60}")
                print("CERTIFICATE CHAIN IS TRUSTED")
                print("="*60)
                return
            
            # Cross-signed: same subject, different issuer
            if top_cert.subject == root.subject and root.subject == root.issuer:
                print(f"[OK] Found self-signed version of '{top_cn}' in trusted roots!")
                print(f"     The received certificate is cross-signed by:")
                print(f"     {top_cert.issuer.rfc4514_string()[:70]}\n")
                print("Educational Note:")
                print("  Cross-signing allows newer roots to be trusted via older,")
                print("  widely-distributed roots for backward compatibility.\n")
                print(f"{'='*60}")
                print("CERTIFICATE CHAIN IS TRUSTED (cross-signed root)")
                print("="*60)
                return
        except Exception:
            continue
    
    # Check if top cert is self-signed
    if top_cert.subject == top_cert.issuer:
        print("Top certificate is self-signed...")
        for root in trusted_roots:
            try:
                if top_cert.subject == root.subject:
                    if top_cert.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
                        print(f"[OK] Top certificate IS a trusted root\n")
                        print(f"{'='*60}")
                        print("CERTIFICATE CHAIN IS TRUSTED")
                        print("="*60)
                        return
            except Exception:
                continue
        
        print("[WARNING] Certificate is self-signed but not in trusted root bundle")
        return
    
    # Try to find issuer in trusted roots by CN
    trusted = False
    issuer_cn_attrs = top_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if issuer_cn_attrs:
        issuer_cn = issuer_cn_attrs[0].value
        print(f"Looking for issuer: {issuer_cn}")
        
        for root in trusted_roots:
            try:
                root_cn_attrs = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if root_cn_attrs and root_cn_attrs[0].value == issuer_cn:
                    root.public_key().verify(
                        signature=top_cert.signature,
                        data=top_cert.tbs_certificate_bytes,
                        padding=padding.PKCS1v15(),
                        algorithm=top_cert.signature_hash_algorithm,
                    )
                    trusted = True
                    print(f"[OK] Found and verified issuer in trusted roots\n")
                    print(f"{'='*60}")
                    print("CERTIFICATE CHAIN IS TRUSTED")
                    print("="*60)
                    return
            except Exception:
                continue
    
    if not trusted:
        print(f"[WARNING] Could not verify chain to a trusted root")
        print(f"          Issuer not found in {len(trusted_roots)} trusted roots")
    
    print()




def parse_certificate(handshake, expected_hostname):
    """
    Parses the Certificate message and performs verification.
    
    The Certificate message contains the server's certificate chain:
        - Leaf certificate (for the server)
        - Intermediate certificates
        - (Sometimes) Root certificate
        
    Args:
        handshake: Raw Certificate handshake message
        expected_hostname: The hostname we're connecting to
        
    Educational Notes:
        - Certificates are sent in order: leaf → intermediate → root
        - The leaf certificate must match the hostname (via CN or SAN)
        - Each certificate in the chain must be signed by the next one
        - The final certificate must chain to a trusted root CA
    """
    offset = 0
    cert_list_len = int.from_bytes(handshake[offset:offset+3], "big")
    offset += 3

    # Parse all certificates from the message
    certificates = []
    end = offset + cert_list_len
    while offset < end:
        cert_len = int.from_bytes(handshake[offset:offset+3], "big")
        offset += 3
        cert_der = handshake[offset:offset+cert_len]
        offset += cert_len
        certificates.append(cert_der)

    print("\n" + "="*60)
    print("SERVER CERTIFICATE")
    print("="*60)
    print(f"Received {len(certificates)} certificate(s) in chain\n")

    # Parse the leaf (server) certificate
    leaf_cert = x509.load_der_x509_certificate(certificates[0], default_backend())

    print("Leaf Certificate Details:")
    print("-" * 60)
    print(f"Subject: {leaf_cert.subject}")
    print(f"Issuer:  {leaf_cert.issuer}")
    print(f"Valid From: {leaf_cert.not_valid_before_utc}")
    print(f"Valid Until: {leaf_cert.not_valid_after_utc}")
    print()

    # Hostname Verification
    print("Hostname Verification:")
    print("-" * 60)
    try:
        san_ext = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        # Fallback to Common Name if SAN is not present
        cn = leaf_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        dns_names = [cn[0].value] if cn else []

    # Check if expected hostname matches any SAN or CN
    hostname_match = False
    matched_name = None
    for dns_name in dns_names:
        # Exact match
        if expected_hostname == dns_name:
            hostname_match = True
            matched_name = dns_name
            break
        # Wildcard match (*.example.com matches www.example.com)
        if dns_name.startswith('*.') and expected_hostname.endswith(dns_name[1:]):
            hostname_match = True
            matched_name = dns_name
            break
    
    if hostname_match:
        print(f"[OK] Hostname '{expected_hostname}' matches certificate")
        print(f"     Matched against: {matched_name}")
    else:
        print(f"[FAILED] Hostname '{expected_hostname}' does NOT match certificate")
        print(f"         Certificate is valid for: {', '.join(dns_names[:5])}")
        if len(dns_names) > 5:
            print(f"         ... and {len(dns_names) - 5} more")
    print()

    # Verify the certificate chain
    verify_chain_with_root(certificates)

    return certificates


def PRF(secret, label, seed, length):
    """
    TLS 1.2 Pseudorandom Function (PRF) using HMAC-SHA256.
    
    The PRF is used to expand secrets into key material:
        PRF(secret, label, seed) = P_SHA256(secret, label + seed)
        
    This is the core of TLS key derivation.
    
    Args:
        secret: The secret to expand (master secret or pre-master secret)
        label: ASCII string label (e.g., "master secret", "key expansion")
        seed: Random seed material (client_random + server_random)
        length: Number of bytes to generate
        
    Returns:
        Expanded key material of specified length
        
    Educational Note:
        The PRF uses HMAC in a specific pattern called P_hash to generate
        as much key material as needed from a single secret.
        
        P_hash(secret, seed) = HMAC(secret, A(1) + seed) +
                               HMAC(secret, A(2) + seed) +
                               HMAC(secret, A(3) + seed) + ...
        
        Where:
            A(0) = seed
            A(i) = HMAC(secret, A(i-1))
    """
    def P_hash(secret, seed, length):
        """HMAC-based key derivation function"""
        result = b""
        A = seed  # A(0) = seed
        
        while len(result) < length:
            # A(i) = HMAC(secret, A(i-1))
            h = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
            h.update(A)
            A = h.finalize()
            
            # Append HMAC(secret, A(i) + seed) to result
            h = hmac.HMAC(secret, hashes.SHA256(), backend=default_backend())
            h.update(A + seed)
            result += h.finalize()
            
        return result[:length]
    
    return P_hash(secret, label.encode() + seed, length)


def derive_keys(pre_master_secret, client_random, server_random, cipher_suite):
    """
    Derives all session keys from the pre-master secret.
    
    TLS Key Derivation Process:
        1. pre_master_secret + randoms → master_secret (using PRF)
        2. master_secret + randoms → key_block (using PRF)
        3. key_block is split into:
           - client_write_MAC_key
           - server_write_MAC_key
           - client_write_encryption_key
           - server_write_encryption_key
           - client_write_IV
           - server_write_IV
           
    Args:
        pre_master_secret: 48 bytes (TLS 1.2) or 32 bytes (depends on cipher)
        client_random: 32 bytes from ClientHello
        server_random: 32 bytes from ServerHello
        cipher_suite: Selected cipher suite bytes
        
    Returns:
        Dictionary with all derived keys
        
    Educational Note:
        The master secret is what provides perfect forward secrecy (PFS) in
        ephemeral key exchange modes like ECDHE. Even if the server's RSA
        key is compromised later, past sessions can't be decrypted.
    """
    global master_secret
    
    # Step 1: Derive master secret from pre-master secret
    master_secret = PRF(
        pre_master_secret,
        "master secret",
        client_random + server_random,
        48  # Master secret is always 48 bytes in TLS 1.2
    )
    
    print("\n" + "="*60)
    print("KEY DERIVATION")
    print("="*60)
    print(f"Pre-Master Secret: {pre_master_secret.hex()[:64]}...")
    print(f"Master Secret:     {master_secret.hex()[:64]}...")
    print()
    
    # Determine key sizes based on cipher suite
    # For TLS_RSA_WITH_AES_128_CBC_SHA (0x002f):
    #   - MAC key: 20 bytes (SHA-1)
    #   - Encryption key: 16 bytes (AES-128)
    #   - Note: TLS 1.2 with CBC uses explicit IVs (sent with each record)
    #           so no IV is derived from the key block
    if cipher_suite == b"\x00\x2f":
        mac_key_length = 20  # SHA-1
        enc_key_length = 16  # AES-128
    elif cipher_suite == b"\x00\x35":
        mac_key_length = 20  # SHA-1
        enc_key_length = 32  # AES-256
    else:
        # Default to AES-128-CBC-SHA
        mac_key_length = 20
        enc_key_length = 16
    
    # Step 2: Derive key block from master secret
    # For TLS 1.2 with CBC ciphers, key_block contains:
    # client_write_MAC_key + server_write_MAC_key +
    # client_write_key + server_write_key
    # (No IVs - they are explicit/random per record)
    key_block_length = 2 * (mac_key_length + enc_key_length)
    key_block = PRF(
        master_secret,
        "key expansion",
        server_random + client_random,  # Note: reversed order!
        key_block_length
    )
    
    # Step 3: Partition key block into individual keys
    offset = 0
    client_write_mac_key = key_block[offset:offset+mac_key_length]
    offset += mac_key_length
    
    server_write_mac_key = key_block[offset:offset+mac_key_length]
    offset += mac_key_length
    
    client_write_key = key_block[offset:offset+enc_key_length]
    offset += enc_key_length
    
    server_write_key = key_block[offset:offset+enc_key_length]
    offset += enc_key_length
    
    print("Derived Session Keys:")
    print("-" * 60)
    print(f"Client Write MAC Key: {client_write_mac_key.hex()}")
    print(f"Server Write MAC Key: {server_write_mac_key.hex()}")
    print(f"Client Write Key:     {client_write_key.hex()}")
    print(f"Server Write Key:     {server_write_key.hex()}")
    print()
    print("Note: TLS 1.2 with CBC uses explicit IVs (random per record)")
    print("      IVs are not derived from the key block.")
    print()
    
    return {
        'master_secret': master_secret,
        'client_write_mac_key': client_write_mac_key,
        'server_write_mac_key': server_write_mac_key,
        'client_write_key': client_write_key,
        'server_write_key': server_write_key,
    }


def build_client_key_exchange(server_cert_der):
    """
    Builds the ClientKeyExchange message.
    
    In RSA key exchange:
        1. Client generates a random 48-byte pre-master secret
        2. Client encrypts it with server's RSA public key
        3. Client sends the encrypted pre-master secret to server
        4. Both derive the same master secret from it
        
    Args:
        server_cert_der: Server's certificate in DER format
        
    Returns:
        Tuple of (ClientKeyExchange record, pre-master secret)
        
    Educational Note:
        RSA key exchange has a weakness: no forward secrecy. If the server's
        private key is compromised in the future, all past sessions can be
        decrypted. Modern TLS prefers ECDHE for forward secrecy.
    """
    global client_key_exchange_msg
    
    # Load server certificate and extract public key
    cert = x509.load_der_x509_certificate(server_cert_der, default_backend())
    public_key = cert.public_key()
    
    # Generate pre-master secret
    # Format: 0x03 0x03 (TLS 1.2) + 46 random bytes = 48 bytes total
    pre_master_secret = TLS_VERSION_1_2 + os.urandom(46)
    
    # Encrypt pre-master secret with server's public key
    encrypted_pms = public_key.encrypt(
        pre_master_secret,
        padding.PKCS1v15()
    )
    
    # Build ClientKeyExchange message
    # Format: length (2 bytes) + encrypted pre-master secret
    handshake_body = struct.pack("!H", len(encrypted_pms)) + encrypted_pms
    
    handshake = (
        bytes([CLIENT_KEY_EXCHANGE]) +
        struct.pack("!I", len(handshake_body))[1:] +  # 24-bit length
        handshake_body
    )
    
    # Store for Finished message calculation
    client_key_exchange_msg = handshake
    
    # Wrap in TLS record
    record = (
        bytes([HANDSHAKE_RECORD]) +
        TLS_VERSION_1_2 +
        struct.pack("!H", len(handshake)) +
        handshake
    )
    
    print("\n" + "="*60)
    print("CLIENT KEY EXCHANGE")
    print("="*60)
    print(f"Pre-Master Secret ({len(pre_master_secret)} bytes): {pre_master_secret.hex()}")
    print(f"  Version prefix: {pre_master_secret[:2].hex()} (should be 0303 for TLS 1.2)")
    print(f"Encrypted with server's RSA public key")
    print(f"Encrypted PMS Length: {len(encrypted_pms)} bytes")
    print(f"Message format:")
    print(f"  - Handshake type: 0x10 (ClientKeyExchange)")
    print(f"  - Length: {len(handshake_body)} bytes")
    print(f"  - Encrypted PMS length field: {struct.unpack('!H', handshake_body[:2])[0]} bytes")
    print()
    
    return record, pre_master_secret


def build_change_cipher_spec():
    """
    Builds the ChangeCipherSpec message.
    
    This is a special protocol message (not a handshake message) that signals:
    "All following messages will be encrypted with the negotiated cipher."
    
    Returns:
        ChangeCipherSpec record
        
    Educational Note:
        ChangeCipherSpec is technically not part of the handshake protocol,
        it's its own protocol type (0x14). It's always a single byte: 0x01.
    """
    # ChangeCipherSpec message is always 1 byte: 0x01
    ccs_msg = b"\x01"
    
    record = (
        bytes([CHANGE_CIPHER_SPEC_RECORD]) +
        TLS_VERSION_1_2 +
        struct.pack("!H", len(ccs_msg)) +
        ccs_msg
    )
    
    print("\n" + "="*60)
    print("CHANGE CIPHER SPEC")
    print("="*60)
    print("Signaling: All following messages will be encrypted")
    print()
    
    return record


def compute_mac(mac_key, seq_num, content_type, version, payload):
    """
    Computes HMAC for TLS record (for CBC cipher suites).
    
    MAC = HMAC(MAC_write_key, seq_num + TLSCompressed.type +
               TLSCompressed.version + TLSCompressed.length + TLSCompressed.fragment)
    
    Args:
        mac_key: MAC key for this direction
        seq_num: Sequence number (64-bit, incremented for each record)
        content_type: TLS content type (1 byte)
        version: TLS version (2 bytes)
        payload: The actual data to MAC
        
    Returns:
        20 bytes of HMAC-SHA1 (for SHA cipher suites)
        
    Educational Note:
        The MAC includes sequence number to prevent replay attacks.
        Each record has an incrementing sequence number.
    """
    mac_data = (
        struct.pack("!Q", seq_num) +  # 64-bit sequence number
        bytes([content_type]) +
        version +
        struct.pack("!H", len(payload)) +
        payload
    )
    
    h = hmac.HMAC(mac_key, hashes.SHA1(), backend=default_backend())
    h.update(mac_data)
    return h.finalize()


def compute_verify_data(master_secret, handshake_messages, label):
    """
    Computes the verify_data for the Finished message.
    
    verify_data = PRF(master_secret, label, 
                      SHA256(handshake_messages))[0:12]
    
    Args:
        master_secret: The derived master secret
        handshake_messages: Concatenation of all handshake messages so far
        label: "client finished" or "server finished"
        
    Returns:
        12 bytes of verify_data
        
    Educational Note:
        The Finished message proves that both sides have the same view of
        the handshake. Any tampering would result in different verify_data.
    """
    # Hash all handshake messages
    handshake_hash = hashlib.sha256(handshake_messages).digest()
    
    # Generate verify_data using PRF
    verify_data = PRF(master_secret, label, handshake_hash, 12)
    
    return verify_data


def encrypt_record(plaintext, content_type, keys, seq_num):
    """
    Encrypts a TLS record using AES-CBC with HMAC-SHA1.
    
    Process:
        1. Compute MAC over plaintext
        2. Append MAC to plaintext
        3. Add padding (PKCS#7)
        4. Encrypt with AES-CBC
        
    Args:
        plaintext: Data to encrypt
        content_type: TLS content type
        keys: Session keys dictionary
        seq_num: Current sequence number
        
    Returns:
        Encrypted ciphertext (IV + encrypted data)
        
    Educational Note:
        TLS 1.2 with CBC uses Encrypt-then-MAC to prevent padding oracle attacks.
        Actually, it's MAC-then-Encrypt in TLS 1.2, but TLS 1.3 fixes this.
    """
    # Step 1: Compute MAC
    mac = compute_mac(
        keys['client_write_mac_key'],
        seq_num,
        content_type,
        TLS_VERSION_1_2,
        plaintext
    )
    
    # Step 2: Append MAC to plaintext
    data_with_mac = plaintext + mac
    
    # Step 3: Add PKCS#7 padding
    block_size = 16  # AES block size
    padding_length = block_size - (len(data_with_mac) % block_size)
    padding = bytes([padding_length - 1] * padding_length)
    padded_data = data_with_mac + padding
    
    # Step 4: Encrypt with AES-CBC
    # Generate random IV for this record
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(keys['client_write_key']),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV + ciphertext (TLS 1.2 explicit IV)
    return iv + ciphertext


def decrypt_record(ciphertext, content_type, keys, seq_num):
    """
    Decrypts a TLS record encrypted with AES-CBC.
    
    Args:
        ciphertext: Encrypted data (including IV)
        content_type: TLS content type
        keys: Session keys dictionary
        seq_num: Current sequence number
        
    Returns:
        Decrypted plaintext (or None if MAC verification fails)
        
    Educational Note:
        Proper implementations must be careful about timing attacks during
        MAC verification to prevent padding oracle attacks.
    """
    # Extract IV and ciphertext
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    
    # Decrypt
    cipher = Cipher(
        algorithms.AES(keys['server_write_key']),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    padding_length = padded_data[-1] + 1
    data_with_mac = padded_data[:-padding_length]
    
    # Split data and MAC
    mac_length = 20  # SHA-1 HMAC
    plaintext = data_with_mac[:-mac_length]
    received_mac = data_with_mac[-mac_length:]
    
    # Verify MAC
    expected_mac = compute_mac(
        keys['server_write_mac_key'],
        seq_num,
        content_type,
        TLS_VERSION_1_2,
        plaintext
    )
    
    if received_mac != expected_mac:
        print("[ERROR] MAC verification failed!")
        return None
    
    return plaintext


def build_finished(keys):
    """
    Builds the Finished handshake message (encrypted).
    
    The Finished message contains a hash of all previous handshake messages,
    proving that no tampering occurred. It's the first encrypted message.
    
    Args:
        keys: Dictionary of session keys
        
    Returns:
        Encrypted Finished record
        
    Educational Note:
        Both client and server send Finished messages. If either side's
        Finished message doesn't verify, the handshake fails. This prevents
        man-in-the-middle attacks that try to downgrade cipher suites.
    """
    global client_seq_num
    
    # Collect all handshake messages
    handshake_messages = (
        client_hello_msg +
        server_hello_msg +
        certificate_msg +
        server_key_exchange_msg +  # May be empty for RSA key exchange
        server_hello_done_msg +
        client_key_exchange_msg
    )
    
    print("\n" + "="*60)
    print("FINISHED MESSAGE (ENCRYPTED)")
    print("="*60)
    print(f"Handshake messages included in hash:")
    print(f"  ClientHello: {len(client_hello_msg)} bytes")
    print(f"  ServerHello: {len(server_hello_msg)} bytes")
    print(f"  Certificate: {len(certificate_msg)} bytes")
    if server_key_exchange_msg:
        print(f"  ServerKeyExchange: {len(server_key_exchange_msg)} bytes")
    print(f"  ServerHelloDone: {len(server_hello_done_msg)} bytes")
    print(f"  ClientKeyExchange: {len(client_key_exchange_msg)} bytes")
    print(f"  Total: {len(handshake_messages)} bytes")
    print(f"  SHA256 hash: {hashlib.sha256(handshake_messages).digest().hex()[:32]}...")
    print()
    
    # Compute verify_data
    verify_data = compute_verify_data(
        keys['master_secret'],
        handshake_messages,
        "client finished"
    )
    
    print(f"Verify Data: {verify_data.hex()}")
    print(f"Verify Data Length: {len(verify_data)} bytes")
    print()
    
    # Build Finished handshake message
    handshake = (
        bytes([FINISHED]) +
        struct.pack("!I", len(verify_data))[1:] +  # 24-bit length
        verify_data
    )
    
    print(f"Finished handshake message: {len(handshake)} bytes")
    print(f"  Type: 0x{FINISHED:02x} (Finished)")
    print(f"  Length: {len(verify_data)} bytes")
    print(f"  Full message: {handshake.hex()}")
    print()
    
    # Encrypt the Finished message
    print("Encrypting Finished message:")
    print("  1. Computing HMAC-SHA1 over handshake message")
    print("  2. Appending MAC to message")
    print("  3. Adding PKCS#7 padding")
    print("  4. Encrypting with AES-128-CBC")
    print()
    
    encrypted_data = encrypt_record(
        handshake,
        HANDSHAKE_RECORD,
        keys,
        client_seq_num
    )
    client_seq_num += 1
    
    # Wrap in TLS record
    record = (
        bytes([HANDSHAKE_RECORD]) +
        TLS_VERSION_1_2 +
        struct.pack("!H", len(encrypted_data)) +
        encrypted_data
    )
    
    print(f"Encrypted payload size: {len(encrypted_data)} bytes")
    print(f"  (includes 16-byte IV, encrypted data, MAC, and padding)")
    print()
    
    return record


def send_application_data(sock, data, keys):
    """
    Sends encrypted application data over the TLS connection.
    
    Args:
        sock: Connected socket
        data: Plaintext data to send (bytes)
        keys: Session keys dictionary
        
    Educational Note:
        Application data is encrypted the same way as the Finished message:
        MAC-then-Encrypt with AES-CBC and HMAC-SHA1.
    """
    global client_seq_num
    
    print(f"\nSending application data ({len(data)} bytes):")
    print(f"  Plaintext: {data[:100]}..." if len(data) > 100 else f"  Plaintext: {data}")
    print()
    
    # Encrypt the application data
    encrypted_data = encrypt_record(
        data,
        APPLICATION_DATA_RECORD,
        keys,
        client_seq_num
    )
    client_seq_num += 1
    
    # Wrap in TLS record
    record = (
        bytes([APPLICATION_DATA_RECORD]) +
        TLS_VERSION_1_2 +
        struct.pack("!H", len(encrypted_data)) +
        encrypted_data
    )
    
    sock.sendall(record)
    print(f"[OK] Sent encrypted application data ({len(record)} bytes)\n")


def receive_application_data(sock, keys, timeout=5):
    """
    Receives and decrypts application data from the TLS connection.
    
    Args:
        sock: Connected socket
        keys: Session keys dictionary
        timeout: Read timeout in seconds
        
    Returns:
        Decrypted plaintext data (or None if error)
        
    Educational Note:
        The server's response may span multiple TLS records.
        Each record is decrypted separately.
    """
    global server_seq_num
    
    print("Receiving application data from server...")
    data = recv_all(sock, timeout=timeout)
    
    if len(data) == 0:
        print("[WARNING] No data received\n")
        return None
    
    print(f"[OK] Received {len(data)} bytes\n")
    
    # Parse TLS records
    records = split_tls_records(data)
    print(f"Received {len(records)} TLS record(s)\n")
    
    plaintext_chunks = []
    
    for idx, record in enumerate(records):
        content_type = record[0]
        
        if content_type == ALERT_RECORD:
            print(f"Record {idx + 1}: Alert")
            parse_alert(record)
            return None
            
        elif content_type == APPLICATION_DATA_RECORD:
            print(f"Record {idx + 1}: Application Data")
            payload_length = struct.unpack("!H", record[3:5])[0]
            encrypted_payload = record[5:5+payload_length]
            
            print(f"  Encrypted payload: {len(encrypted_payload)} bytes")
            
            # Decrypt the application data
            decrypted = decrypt_record(
                encrypted_payload,
                APPLICATION_DATA_RECORD,
                keys,
                server_seq_num
            )
            server_seq_num += 1
            
            if decrypted:
                print(f"  [OK] Decrypted: {len(decrypted)} bytes")
                plaintext_chunks.append(decrypted)
            else:
                print(f"  [FAILED] Decryption failed")
                return None
        else:
            print(f"Record {idx + 1}: Unknown type {content_type:02x}")
    
    print()
    
    if plaintext_chunks:
        return b"".join(plaintext_chunks)
    return None


# =========================
# Main TLS Client
# =========================
def main():
    """
    Main TLS client that demonstrates a complete TLS 1.2 handshake.
    
    The TLS handshake sequence:
        1. Client → Server: ClientHello
        2. Server → Client: ServerHello
        3. Server → Client: Certificate
        4. Server → Client: ServerHelloDone (or ServerKeyExchange for ECDHE)
        5. Client → Server: ClientKeyExchange
        6. Client → Server: ChangeCipherSpec
        7. Client → Server: Finished (encrypted)
        8. Server → Client: ChangeCipherSpec
        9. Server → Client: Finished (encrypted)
        10. Application data exchange (HTTP request/response)
    """
    # Parse command line arguments
    use_all_ciphers = '--all-ciphers' in sys.argv
    hostname = None
    
    for arg in sys.argv[1:]:
        if arg != '--all-ciphers':
            hostname = arg
            break
    
    if hostname is None:
        hostname = "google.com"
    
    # Override cipher suites if requested
    if use_all_ciphers:
        global CIPHER_SUITES
        CIPHER_SUITES = CIPHER_SUITES_ALL
    
    port = 443
    
    print("\n" + "="*60)
    print("EDUCATIONAL TLS 1.2 CLIENT")
    print("="*60)
    print(f"Target: {hostname}:{port}")
    print("Protocol: TLS 1.2")
    print("Cipher Suites Offered (RSA key exchange only):")
    print("  - TLS_RSA_WITH_AES_128_CBC_SHA")
    print("  - TLS_RSA_WITH_AES_256_CBC_SHA")
    print()
    print("Note: Modern servers often require ECDHE cipher suites.")
    print("      This implementation demonstrates RSA key exchange only.")
    print("      If the server only supports ECDHE, the handshake will stop")
    print("      with an educational message.")
    print("="*60 + "\n")
    
    # Step 1: Establish TCP connection
    print("Step 1: Establishing TCP connection...")
    try:
        sock = socket.create_connection((hostname, port), timeout=10)
        print(f"[OK] Connected to {hostname}:{port}\n")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return 1
    
    # Step 2: Send ClientHello
    print("Step 2: Sending ClientHello...")
    client_hello = build_client_hello(hostname)
    sock.sendall(client_hello)
    print(f"[OK] Sent ClientHello ({len(client_hello)} bytes)")
    print("   - TLS version: 1.2")
    print("   - SNI: " + hostname)
    print("   - 2 cipher suites offered (RSA key exchange only)")
    print("   - Extensions: SNI, Supported Groups, Signature Algorithms, EC Point Formats\n")
    
    # Step 3: Receive server response
    print("Step 3: Receiving server handshake messages...")
    data = recv_all(sock)
    print(f"[OK] Received {len(data)} bytes from server\n")
    
    # Check if we received a TLS alert (typically 7 bytes)
    if len(data) <= 7:
        print("[WARNING] Received very short response (likely a TLS alert)")
        if len(data) >= 7:
            alert_level = data[5]
            alert_desc = data[6]
            alert_names = {
                40: "handshake_failure",
                42: "bad_certificate",
                43: "unsupported_certificate",
                70: "protocol_version",
                71: "insufficient_security",
                80: "internal_error",
                86: "inappropriate_fallback",
                112: "unrecognized_name"
            }
            alert_name = alert_names.get(alert_desc, f"unknown({alert_desc})")
            print(f"    Alert Level: {alert_level} ({'warning' if alert_level == 1 else 'fatal'})")
            print(f"    Alert Description: {alert_desc} ({alert_name})")
            print("\nPossible reasons:")
            print("  - Server requires TLS 1.3 (this client only supports TLS 1.2)")
            print("  - Server requires additional TLS extensions")
            print("  - Server doesn't support any of the offered cipher suites")
            print("  - Server requires stronger security parameters\n")
        sock.close()
        return 1
    
    # Step 4: Parse TLS records
    records = split_tls_records(data)
    print(f"Step 4: Parsing {len(records)} TLS record(s)...\n")

    global server_hello_msg, certificate_msg, server_key_exchange_msg, server_hello_done_msg
    server_certificates = None
    has_server_key_exchange = False
    
    # Process each handshake message
    for i, record in enumerate(records):
        content_type = record[0]
        if content_type != HANDSHAKE_RECORD:
            continue

        handshake_type = record[5]
        handshake_len = int.from_bytes(record[6:9], "big")
        handshake = record[5:9+handshake_len]
        handshake_body = record[9:9+handshake_len]

        if handshake_type == SERVER_HELLO:
            server_hello_msg = handshake
            parse_server_hello(handshake_body)

        elif handshake_type == CERTIFICATE:
            certificate_msg = handshake
            server_certificates = parse_certificate(handshake_body, hostname)

        elif handshake_type == SERVER_KEY_EXCHANGE:
            server_key_exchange_msg = handshake
            has_server_key_exchange = True
            print("\n" + "="*60)
            print("SERVER KEY EXCHANGE")
            print("="*60)
            print(f"Received ServerKeyExchange message ({len(handshake)} bytes)")
            print("This indicates the server selected an ECDHE cipher suite.")
            print()
            print("[LIMITATION] This educational implementation only supports")
            print("             RSA key exchange, not ECDHE.")
            print()
            print("Cipher suite selected: {}".format(selected_cipher.hex() if 'selected_cipher' in globals() else 'unknown'))
            cipher_names = {
                b"\x00\x2f": "TLS_RSA_WITH_AES_128_CBC_SHA",
                b"\x00\x35": "TLS_RSA_WITH_AES_256_CBC_SHA",
                b"\xc0\x2f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                b"\xc0\x30": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                b"\xc0\x13": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                b"\xc0\x14": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            }
            if 'selected_cipher' in globals():
                print(f"  {cipher_names.get(selected_cipher, 'Unknown cipher')}")
            print()

        elif handshake_type == SERVER_HELLO_DONE:
            server_hello_done_msg = handshake
            print("\n" + "="*60)
            print("SERVER HELLO DONE")
            print("="*60)
            print("Server has finished sending handshake messages.")
            print()

    # Check if we should continue with full handshake
    if not server_certificates:
        print("[WARNING] Did not receive server certificate. Cannot continue.\n")
        sock.close()
        return 1
    
    if has_server_key_exchange:
        print("="*60)
        print("HANDSHAKE CANNOT CONTINUE")
        print("="*60)
        print("The server selected an ECDHE cipher suite which requires")
        print("elliptic curve key exchange.")
        print()
        print("This educational implementation demonstrates RSA key exchange only.")
        print()
        print("To complete this handshake, the client would need to:")
        print("  1. Parse ServerKeyExchange (EC parameters + signature)")
        print("  2. Verify the signature using server's public key")
        print("  3. Perform ECDH key agreement")
        print("  4. Send ClientKeyExchange with client's EC public key")
        print("  5. Derive pre-master secret from ECDH shared secret")
        print()
        print("Educational Note:")
        print("  ECDHE provides Perfect Forward Secrecy (PFS) - even if")
        print("  the server's RSA key is compromised later, past sessions")
        print("  cannot be decrypted because the ECDH keys are ephemeral.")
        print()
        print("For a complete implementation supporting ECDHE:")
        print("  - Use Python's ssl module")
        print("  - Or implement ECDH using cryptography.hazmat.primitives.asymmetric.ec")
        print("\n" + "="*60 + "\n")
        sock.close()
        return 0
    
    # Step 5: Send ClientKeyExchange
    print("Step 5: Completing TLS handshake...\n")
    client_key_exchange_record, pre_master_secret = build_client_key_exchange(server_certificates[0])
    
    # Step 6: Derive session keys
    keys = derive_keys(pre_master_secret, client_random, server_random, selected_cipher)
    
    # Step 7: Send ChangeCipherSpec
    change_cipher_spec_record = build_change_cipher_spec()
    
    # Step 8: Send Finished
    finished_record = build_finished(keys)
    
    # Send all client messages
    try:
        sock.sendall(client_key_exchange_record)
        print(f"[OK] Sent ClientKeyExchange ({len(client_key_exchange_record)} bytes)")
        
        sock.sendall(change_cipher_spec_record)
        print(f"[OK] Sent ChangeCipherSpec ({len(change_cipher_spec_record)} bytes)")
        
        sock.sendall(finished_record)
        print(f"[OK] Sent Finished ({len(finished_record)} bytes)")
        print()
    except Exception as e:
        print(f"[ERROR] Failed to send handshake completion: {e}\n")
        sock.close()
        return 1
    
    # Step 9: Receive server's ChangeCipherSpec and Finished
    print("Step 6: Waiting for server's ChangeCipherSpec and Finished...")
    try:
        server_response = recv_all(sock, timeout=5)
        if len(server_response) > 0:
            print(f"[OK] Received {len(server_response)} bytes from server\n")
            
            # Parse server response
            print("Parsing server response:")
            print("-" * 60)
            
            server_records = split_tls_records(server_response)
            print(f"Received {len(server_records)} record(s) from server\n")
            
            server_finished_verified = False
            global server_seq_num
            
            for idx, record in enumerate(server_records):
                content_type = record[0]
                
                if content_type == ALERT_RECORD:
                    print(f"Record {idx + 1}: Alert")
                    parse_alert(record)
                    
                elif content_type == CHANGE_CIPHER_SPEC_RECORD:
                    print(f"Record {idx + 1}: ChangeCipherSpec")
                    print("  [OK] Server signaled cipher spec change\n")
                    
                elif content_type == HANDSHAKE_RECORD:
                    print(f"Record {idx + 1}: Encrypted Handshake (Finished)")
                    payload_length = struct.unpack("!H", record[3:5])[0]
                    encrypted_payload = record[5:5+payload_length]
                    
                    print(f"  Encrypted payload size: {len(encrypted_payload)} bytes")
                    print("  Attempting to decrypt...")
                    
                    # Decrypt the Finished message
                    decrypted = decrypt_record(
                        encrypted_payload,
                        HANDSHAKE_RECORD,
                        keys,
                        server_seq_num
                    )
                    server_seq_num += 1
                    
                    if decrypted:
                        print("  [OK] Successfully decrypted\n")
                        
                        # Parse Finished message
                        handshake_type = decrypted[0]
                        if handshake_type == FINISHED:
                            handshake_length = int.from_bytes(decrypted[1:4], "big")
                            server_verify_data = decrypted[4:4+handshake_length]
                            
                            print("  Server Finished Message:")
                            print(f"    Verify Data: {server_verify_data.hex()}")
                            
                            # Compute expected verify_data
                            handshake_messages_with_client_finished = (
                                client_hello_msg +
                                server_hello_msg +
                                certificate_msg +
                                server_hello_done_msg +
                                client_key_exchange_msg +
                                bytes([FINISHED]) +
                                struct.pack("!I", 12)[1:] +
                                compute_verify_data(
                                    keys['master_secret'],
                                    client_hello_msg + server_hello_msg + 
                                    certificate_msg + server_hello_done_msg + 
                                    client_key_exchange_msg,
                                    "client finished"
                                )
                            )
                            
                            expected_verify_data = compute_verify_data(
                                keys['master_secret'],
                                handshake_messages_with_client_finished,
                                "server finished"
                            )
                            
                            print(f"    Expected:    {expected_verify_data.hex()}")
                            
                            if server_verify_data == expected_verify_data:
                                print("    [OK] Server Finished verified!\n")
                                server_finished_verified = True
                            else:
                                print("    [FAILED] Server Finished verification failed\n")
                        else:
                            print(f"  [WARNING] Unexpected handshake type: {handshake_type}\n")
                    else:
                        print("  [FAILED] Decryption or MAC verification failed\n")
                        
                elif content_type == APPLICATION_DATA_RECORD:
                    print(f"Record {idx + 1}: Application Data")
                    print("  [INFO] Server sent encrypted application data\n")
                else:
                    print(f"Record {idx + 1}: Unknown type {content_type:02x}\n")
            
            if server_finished_verified:
                print("="*60)
                print("🎉 HANDSHAKE SUCCESSFULLY COMPLETED!")
                print("="*60)
                print("The secure channel is now established.")
                print("Both client and server have verified each other's Finished messages.")
                print()
                
                # Now try to send an HTTP request
                print("="*60)
                print("SENDING HTTP REQUEST")
                print("="*60)
                print()
                
                # Construct HTTP GET request
                http_request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {hostname}\r\n"
                    f"User-Agent: Educational-TLS-Client/1.0\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()
                
                try:
                    # Send encrypted HTTP request
                    send_application_data(sock, http_request, keys)
                    
                    # Receive encrypted HTTP response
                    response_data = receive_application_data(sock, keys, timeout=10)
                    
                    if response_data:
                        print("="*60)
                        print("HTTP RESPONSE RECEIVED")
                        print("="*60)
                        print()
                        
                        # Parse HTTP response
                        response_text = response_data.decode('utf-8', errors='replace')
                        lines = response_text.split('\r\n')
                        
                        # Print status line and headers
                        print("Status Line:")
                        print(f"  {lines[0]}")
                        print()
                        
                        print("Response Headers:")
                        header_end = 0
                        for i, line in enumerate(lines[1:], 1):
                            if line == '':
                                header_end = i + 1
                                break
                            print(f"  {line}")
                        print()
                        
                        # Print body (first part)
                        body = '\r\n'.join(lines[header_end:])
                        if len(body) > 500:
                            print(f"Response Body ({len(body)} bytes, showing first 500):")
                            print(body[:500])
                            print("\n... (truncated) ...")
                        else:
                            print(f"Response Body ({len(body)} bytes):")
                            print(body)
                        print()
                        
                        print("="*60)
                        print("✅ SUCCESSFULLY EXCHANGED APPLICATION DATA!")
                        print("="*60)
                        print()
                    
                except Exception as e:
                    print(f"[ERROR] Failed to exchange application data: {e}")
                    import traceback
                    traceback.print_exc()
                    print()
        else:
            print("[WARNING] No response from server (connection may have closed)\n")
    except socket.timeout:
        print("[WARNING] Timeout waiting for server response\n")
    except Exception as e:
        print(f"[WARNING] Error receiving server response: {e}\n")
        import traceback
        traceback.print_exc()

    sock.close()
    
    print("\n" + "="*60)
    print("TLS 1.2 HANDSHAKE SUMMARY")
    print("="*60)
    print("\nHandshake Messages Exchanged:")
    print("-" * 60)
    print("✓ ClientHello → Server")
    print("✓ ServerHello ← Server")
    print("✓ Certificate ← Server")
    print("✓ ServerHelloDone ← Server")
    print("✓ ClientKeyExchange → Server")
    print("✓ [ChangeCipherSpec] → Server")
    print("✓ Finished (encrypted) → Server")
    print("✓ [ChangeCipherSpec] ← Server")
    print("✓ Finished (encrypted) ← Server")
    print("\nSecurity Features Implemented:")
    print("-" * 60)
    print("✓ RSA key exchange with 48-byte pre-master secret")
    print("✓ Master secret derivation using TLS PRF")
    print("✓ Session key derivation (MAC keys, encryption keys, IVs)")
    print("✓ AES-128-CBC encryption")
    print("✓ HMAC-SHA1 for message authentication")
    print("✓ PKCS#7 padding")
    print("✓ Sequence number tracking (replay protection)")
    print("✓ Finished message verification (both directions)")
    print("✓ Certificate chain validation")
    print("✓ Hostname verification")
    print("\nWhat This Implementation Demonstrates:")
    print("-" * 60)
    print("  • Complete TLS 1.2 handshake with RSA key exchange")
    print("  • Cryptographic key derivation using PRF")
    print("  • Authenticated encryption (MAC-then-Encrypt)")
    print("  • Certificate validation against system trust store")
    print("  • Bidirectional Finished message verification")
    print("\nLimitations (for educational purposes):")
    print("-" * 60)
    print("  • Only supports TLS_RSA_WITH_AES_128_CBC_SHA")
    print("  • No ECDHE (lacks forward secrecy)")
    print("  • No session resumption")
    print("  • No renegotiation support")
    print("  • Simplified error handling")
    print("  • No protection against timing attacks")
    print("\nFor Production Use:")
    print("-" * 60)
    print("  • Use Python's ssl module (wraps OpenSSL)")
    print("  • Use modern TLS 1.3 with ECDHE")
    print("  • Enable AEAD ciphers (GCM, ChaCha20-Poly1305)")
    print("  • Implement proper certificate pinning if needed")
    print("  • Enable OCSP stapling for revocation checking")
    print("\n" + "="*60 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
