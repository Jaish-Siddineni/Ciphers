import string
import numpy as np

# Caesar Cipher
def caesar_encrypt(plain_text, shift):
    result = ''
    for char in plain_text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def caesar_decrypt(cipher_text, shift):
    return caesar_encrypt(cipher_text, -shift)

# Vigenère Cipher
def vigenere_encrypt(plain_text, key):
    result = []
    key = (key * (len(plain_text) // len(key))) + key[:len(plain_text) % len(key)]
    for pt_char, key_char in zip(plain_text, key):
        if pt_char.isalpha():
            shift = ord(key_char.lower()) - 97
            if pt_char.isupper():
                result.append(chr((ord(pt_char) - 65 + shift) % 26 + 65))
            else:
                result.append(chr((ord(pt_char) - 97 + shift) % 26 + 97))
        else:
            result.append(pt_char)
    return ''.join(result)

def vigenere_decrypt(cipher_text, key):
    result = []
    key = (key * (len(cipher_text) // len(key))) + key[:len(cipher_text) % len(key)]
    for ct_char, key_char in zip(cipher_text, key):
        if ct_char.isalpha():
            shift = ord(key_char.lower()) - 97
            if ct_char.isupper():
                result.append(chr((ord(ct_char) - 65 - shift) % 26 + 65))
            else:
                result.append(chr((ord(ct_char) - 97 - shift) % 26 + 97))
        else:
            result.append(ct_char)
    return ''.join(result)

# Hill Cipher
class HillCipher:
    def __init__(self, key_matrix):
        self.key_matrix = np.array(key_matrix)
        if self.key_matrix.shape[0] != self.key_matrix.shape[1]:
            raise ValueError("Key matrix must be square.")
        if np.gcd(int(round(np.linalg.det(self.key_matrix))), 26) != 1:
            raise ValueError("Key matrix must be invertible under mod 26.")

    def encrypt(self, text):
        text = text.lower().replace(" ", "x")
        vector = [ord(c) - ord('a') for c in text if c in string.ascii_lowercase]

        if len(vector) % len(self.key_matrix) != 0:
            vector += [0] * (len(self.key_matrix) - len(vector) % len(self.key_matrix))

        vector = np.array(vector).reshape(-1, len(self.key_matrix))
        encrypted_vector = np.dot(vector, self.key_matrix) % 26
        encrypted_text = ''.join(chr(c + ord('a')) for c in encrypted_vector.flatten())
        return encrypted_text

    def mod_inverse(self, matrix, mod):
        det = int(round(np.linalg.det(matrix)))
        det_inv = pow(det, -1, mod)
        adjugate = np.round(np.linalg.inv(matrix) * det).astype(int)
        return (det_inv * adjugate) % mod

    def decrypt(self, text):
        inverse_key = self.mod_inverse(self.key_matrix, 26)
        vector = [ord(c) - ord('a') for c in text if c in string.ascii_lowercase]
        vector = np.array(vector).reshape(-1, len(self.key_matrix))
        decrypted_vector = np.dot(vector, inverse_key) % 26
        decrypted_text = ''.join(chr(c + ord('a')) for c in decrypted_vector.flatten())
        return decrypted_text.replace('x', ' ').strip()

# User Input Section
def main():
    print("\n===== Encryption & Decryption Program =====")
    print("1. Caesar Cipher")
    print("2. Vigenère Cipher")
    print("3. Hill Cipher")
    choice = input("Choose an option (1/2/3): ").strip()
    if choice == "1":
        # Caesar Cipher
        text = input("\nEnter text: ")
        shift = int(input("Enter shift value: "))
        encrypted_text = caesar_encrypt(text, shift)
        decrypted_text = caesar_decrypt(encrypted_text, shift)
        print(f"\nEncrypted Text: {encrypted_text}")
        print(f"Decrypted Text: {decrypted_text}")

    elif choice == "2":
        # Vigenère Cipher
        text = input("\nEnter text: ")
        key = input("Enter key (letters only): ").upper()
        if not key.isalpha():
            print("Invalid key! Please enter only letters.")
            return
        encrypted_text = vigenere_encrypt(text, key)
        decrypted_text = vigenere_decrypt(encrypted_text, key)
        print(f"\nEncrypted Text: {encrypted_text}")
        print(f"Decrypted Text: {decrypted_text}")

    elif choice == "3":
        # Hill Cipher
        text = input("\nEnter text (only lowercase letters, no special characters): ").lower().replace(" ", "x")

        # Using an invertible key matrix
        key_matrix = [[3, 3], [2, 5]]  # This matrix is valid under mod 26
        cipher = HillCipher(key_matrix)

        encrypted_text = cipher.encrypt(text)
        decrypted_text = cipher.decrypt(encrypted_text)

        print(f"\nEncrypted Text: {encrypted_text}")
        print(f"Decrypted Text: {decrypted_text}")

    else:
        print("Invalid choice! Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
