#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify

def decrypt_block(oracle, prev_block, block, block_index):
    
    deciphered = bytearray(16)
    intermediate = bytearray(16)

    for byte_index in range(1, 17):
        for guess in range(256):
            padding_byte = byte_index
            attack_block = bytearray(16)

            # Prepare the attack block
            for i in range(1, byte_index):
                attack_block[-i] = intermediate[-i] ^ padding_byte
            
            attack_block[-byte_index] = guess
            test_block = attack_block + block

            if oracle.decrypt(test_block) == "Valid":
                intermediate[-byte_index] = guess ^ padding_byte
                deciphered[-byte_index] = prev_block[-byte_index] ^ intermediate[-byte_index]
                break

    print(f"Cipher{block_index}: {block.hex()}")
    print(f"Decrypted Block {block_index}: {bytes(deciphered)}")
    return bytes(deciphered)

class PaddingOracle:
    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        ciphertext = self.s.recv(4096).decode().strip()
        self.iv_and_ctext = unhexlify(ciphertext)
        self.block_size = 16

    def decrypt(self, ctext: bytes) -> str:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self) -> str:
        resp = self.s.recv(4096).decode().strip()
        return resp

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()
        
def xor(first, second):
    return bytearray(x ^ y for x, y in zip(first, second))



def decrypt_message(oracle):
    """Decrypt the entire message block by block."""
    blocks = [oracle.iv_and_ctext[i:i+16] for i in range(0, len(oracle.iv_and_ctext), 16)]
    decrypted_message = b""

    for i in range(1, len(blocks)):
        decrypted_block = decrypt_block(oracle, blocks[i-1], blocks[i], i)
        decrypted_message += decrypted_block

    # Analyze padding in the last block
    padding_byte = decrypted_message[-1]
    padding = padding_byte if all(b == padding_byte for b in decrypted_message[-padding_byte:]) else 0

    print(f"Dec Message with padding: {decrypted_message}")
    print(f"Padding size: {padding} bytes")
    
    if padding > 0 and padding <= 16:  # 16 is the block size
        decrypted_message = decrypted_message[:-padding]
    
    # Convert from bytes to string, handling errors if any non-utf8 data
    try:
        decrypted_message = decrypted_message.decode('utf-8')
    except UnicodeDecodeError:
        # Handle the possibility of non-utf8 encoded bytes in the plaintext
        decrypted_message = "Decrypted message contains non-text bytes."
    
    print(f"Final Dec without padding: {decrypted_message}")
    return decrypted_message

if __name__ == "__main__":
    oracle = PaddingOracle('10.9.0.80', 6000)
    decrypted_message = decrypt_message(oracle)
