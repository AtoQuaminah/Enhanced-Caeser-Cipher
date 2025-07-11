import os
import base64
import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Corrected prime number generation with balanced parentheses
def generate_primes(start, end):
    primes = []
    for num in range(start, end + 1):
        if num > 1:
            is_prime = True
            for i in range(2, int(num**0.5) + 1):
                if num % i == 0:
                    is_prime = False
                    break
            if is_prime:
                primes.append(num)
    return primes

PRIMES = generate_primes(13, 999)

class SecurityException(Exception):
    """Custom security exception"""
    pass

class EnhancedCaesarCipher:
    def __init__(self, password: str):
        self.password = password
        self.SALT_SIZE = 16
        self.MAC_SIZE = 32
        
    def derive_key(self, salt: bytes) -> bytes:
        """Secure key derivation with PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        return kdf.derive(self.password.encode())
    
    def prime_shift_transform(self, data: bytes, key: bytes) -> bytes:
        """Prime-based position-dependent transformation"""
        prime_index = struct.unpack('>H', key[:2])[0] % len(PRIMES)
        prime_key = PRIMES[prime_index]
        
        output = bytearray()
        for i, byte in enumerate(data):
            # Position-dependent offset
            offset = (prime_key * (i+1)) % 256
            transformed_byte = (byte + offset) % 256
            output.append(transformed_byte)
            
            # Digit replacement at prime positions
            if (i + 1) % prime_key == 0:
                # Convert to digit string
                digit_str = str(transformed_byte).encode()
                output.extend(digit_str)
                
                # Add random nulls
                null_count = (prime_key + i) % 3
                output.extend(b'\x00' * null_count)
                
        return bytes(output)
    
    def inverse_prime_shift(self, data: bytes, key: bytes) -> bytes:
        """Reverse the prime-based transformation"""
        prime_index = struct.unpack('>H', key[:2])[0] % len(PRIMES)
        prime_key = PRIMES[prime_index]
        
        output = bytearray()
        i = 0
        position = 0
        
        while i < len(data):
            position += 1
            # Skip null bytes
            if data[i] == 0:
                i += 1
                continue
                
            # Handle digit replacement
            if position % prime_key == 0:
                # Find end of digit sequence
                j = i
                while j < len(data) and data[j] in b'0123456789':
                    j += 1
                
                # Extract digit value
                digit_value = int(data[i:j])
                
                # Reverse transformation
                offset = (prime_key * position) % 256
                original_byte = (digit_value - offset) % 256
                output.append(original_byte)
                
                # Skip nulls
                null_count = (prime_key + position - 1) % 3
                i = j + null_count
            else:
                # Standard byte reversal
                offset = (prime_key * position) % 256
                original_byte = (data[i] - offset) % 256
                output.append(original_byte)
                i += 1
                
        return bytes(output)
    
    def encrypt(self, plaintext: str) -> str:
        """Full encryption workflow"""
        try:
            # Generate random salt
            salt = os.urandom(self.SALT_SIZE)
            
            # Derive key
            key = self.derive_key(salt)
            
            # Convert to bytes
            data = plaintext.encode()
            
            # Apply prime transformation
            transformed = self.prime_shift_transform(data, key)
            
            # HMAC for integrity
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(salt + transformed)
            mac = h.finalize()
            
            # Combine components
            payload = salt + transformed + mac
            return base64.b64encode(payload).decode()
            
        except Exception as e:
            raise SecurityException(f"Encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """Full decryption workflow"""
        try:
            # Decode base64
            payload = base64.b64decode(encrypted_data)
            
            # Split components
            salt = payload[:self.SALT_SIZE]
            transformed = payload[self.SALT_SIZE:-self.MAC_SIZE]
            mac = payload[-self.MAC_SIZE:]
            
            # Derive key
            key = self.derive_key(salt)
            
            # Verify HMAC
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(salt + transformed)
            h.verify(mac)
            
            # Apply inverse transformation
            original_data = self.inverse_prime_shift(transformed, key)
            
            return original_data.decode()
            
        except Exception as e:
            raise SecurityException(f"Decryption failed: {str(e)}")