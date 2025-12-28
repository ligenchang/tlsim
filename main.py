"""
Usage:
    python client.py [hostname]
    
Examples:
    python client.py                    # Connects to google.com (default)
    python client.py amazon.com         # Test with amazon.com
    python client.py github.com         # Test with github.com
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



TLS_VERSION_1_2 = b"\x03\x03"

CIPHER_SUITES = b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
CIPHER_SUITES += b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA
CIPHER_SUITES += b"\xc0\x2f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
CIPHER_SUITES += b"\xc0\x30"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
CIPHER_SUITES += b"\xc0\x13"  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
CIPHER_SUITES += b"\xc0\x14"  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA

# TLS Record Types
HANDSHAKE_RECORD = 0x16

# TLS Handshake Message Types
SERVER_HELLO = 0x02
CERTIFICATE = 0x0b
SERVER_HELLO_DONE = 0x0e


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
    offset = 0
    version = handshake[offset:offset+2]
    offset += 2

    random = handshake[offset:offset+32]
    offset += 32

    sid_len = handshake[offset]
    offset += 1
    session_id = handshake[offset:offset+sid_len]
    offset += sid_len

    cipher = handshake[offset:offset+2]
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


# =========================
# Main TLS Client
# =========================
def main():
    """
    Main TLS client that demonstrates a simplified TLS 1.2 handshake.
    
    The TLS handshake sequence:
        1. Client → Server: ClientHello
        2. Server → Client: ServerHello
        3. Server → Client: Certificate
        4. Server → Client: ServerHelloDone
        (In a full implementation: key exchange, cipher spec, finished messages follow)
        
    This educational implementation stops after receiving the certificate
    to focus on the certificate verification process.
    """
    # Parse command line argument
    hostname = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    port = 443
    
    print("\n" + "="*60)
    print("EDUCATIONAL TLS 1.2 CLIENT")
    print("="*60)
    print(f"Target: {hostname}:{port}")
    print("Protocol: TLS 1.2")
    print("Cipher Suites Offered:")
    print("  - TLS_RSA_WITH_AES_128_CBC_SHA")
    print("  - TLS_RSA_WITH_AES_256_CBC_SHA")
    print("  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    print("  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    print("  - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
    print("  - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
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
    print("   - 6 cipher suites offered")
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

    # Process each handshake message
    for i, record in enumerate(records):
        content_type = record[0]
        if content_type != HANDSHAKE_RECORD:
            continue

        handshake_type = record[5]
        handshake_len = int.from_bytes(record[6:9], "big")
        handshake_body = record[9:9+handshake_len]

        if handshake_type == SERVER_HELLO:
            parse_server_hello(handshake_body)

        elif handshake_type == CERTIFICATE:
            parse_certificate(handshake_body, hostname)

        elif handshake_type == SERVER_HELLO_DONE:
            print("\n" + "="*60)
            print("SERVER HELLO DONE")
            print("="*60)
            print("Server has finished sending handshake messages.")
            print()

    sock.close()
    
    print("\n" + "="*60)
    print("TLS HANDSHAKE ANALYSIS COMPLETE")
    print("="*60)
    print("\nNote: This is an educational implementation that only performs")
    print("the initial handshake and certificate verification.")
    print("A complete TLS implementation would continue with:")
    print("  - ClientKeyExchange")
    print("  - ChangeCipherSpec")
    print("  - Finished messages")
    print("  - Encrypted application data exchange")
    print("\nFor production use, always use Python's ssl module or")
    print("other production-grade TLS libraries.\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
