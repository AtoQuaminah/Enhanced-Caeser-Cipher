import unittest
from crypto_engine import EnhancedCaesarCipher, SecurityException

class TestEnhancedCaesarCipher(unittest.TestCase):
    def setUp(self):
        self.password = "SecurePassw0rd!123"
        self.test_messages = [
            "Hello World!",
            "Enhanced Caesar Cipher",
            "123 Special Ch@rs!",
            "Prime number transformation",
            "Test with\nnewline"
        ]
    
    def test_encryption_decryption(self):
        """Test round-trip encryption/decryption"""
        for msg in self.test_messages:
            with self.subTest(msg=msg):
                cipher = EnhancedCaesarCipher(self.password)
                encrypted = cipher.encrypt(msg)
                decrypted = cipher.decrypt(encrypted)
                self.assertEqual(msg, decrypted)
    
    def test_tamper_protection(self):
        """Test HMAC tamper detection"""
        cipher = EnhancedCaesarCipher(self.password)
        encrypted = cipher.encrypt("Tamper test")
        
        # Tamper with ciphertext
        tampered = encrypted[:-5] + "ABCDE"
        
        with self.assertRaises(SecurityException):
            cipher.decrypt(tampered)
    
    def test_password_verification(self):
        """Test decryption fails with wrong password"""
        cipher1 = EnhancedCaesarCipher(self.password)
        encrypted = cipher1.encrypt("Password test")
        
        cipher2 = EnhancedCaesarCipher("WrongPassword!123")
        with self.assertRaises(SecurityException):
            cipher2.decrypt(encrypted)
    
    def test_empty_message(self):
        """Test handling of empty message"""
        cipher = EnhancedCaesarCipher(self.password)
        encrypted = cipher.encrypt("")
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual("", decrypted)

if __name__ == '__main__':
    unittest.main()