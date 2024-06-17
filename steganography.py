"""
Acest fișier definește clasa Steganography, care implementează metode pentru ascunderea și extragerea mesajelor în/din imagini folosind metoda Least Significant Bit (LSB).
Include, de asemenea, funcționalități pentru a calcula hash-ul SHA-256 al unei imagini, pentru a verifica integritatea acesteia.
Metodele principale sunt:
- `encode_image`: codifică un mesaj într-o imagine folosind LSB.
- `decode_image`: decodifică un mesaj ascuns într-o imagine folosind LSB.
- `calculate_hash`: calculează hash-ul SHA-256 al unei imagini.
"""

import numpy as np
from PIL import Image
import random
import hashlib


class Steganography:
    @staticmethod
    def encode_image(image_path, data, output_path, password):
        """
        Codifică un mesaj într-o imagine folosind metoda LSB.

        :param image_path: Calea către imaginea originală.
        :param data: Datele de codificat (bytearray).
        :param output_path: Calea unde va fi salvată imaginea codificată.
        :param password: Parola folosită pentru generarea unui seed pentru randomizare.
        """
        # Deschide imaginea originală
        image = Image.open(image_path)
        pixels = np.array(image)

        # Adăugăm un delimitator la începutul și sfârșitul mesajului pentru a marca limitele acestuia
        data = b"@START@" + data + b"@END@"

        # Convertim datele în format binar
        binary_data = ''.join(format(byte, '08b') for byte in data)
        data_len = len(binary_data)

        # Setăm seed-ul pentru randomizare pe baza parolei
        random.seed(password)
        indices = list(range(pixels.size // 3))
        random.shuffle(indices)

        # Aplatizăm pixelii imaginii pentru a-i procesa mai ușor
        flat_pixels = pixels.flatten()
        index = 0

        # Parcurgem fiecare pixel și înlocuim bitul cel mai puțin semnificativ cu bitul din mesajul binar
        for i in indices:
            if index < data_len:
                flat_pixels[i * 3] = (flat_pixels[i * 3] & ~1) | int(binary_data[index])
                index += 1
            if index < data_len:
                flat_pixels[i * 3 + 1] = (flat_pixels[i * 3 + 1] & ~1) | int(binary_data[index])
                index += 1
            if index < data_len:
                flat_pixels[i * 3 + 2] = (flat_pixels[i * 3 + 2] & ~1) | int(binary_data[index])
                index += 1

        # Reconstruim imaginea codificată și o salvăm la calea specificată
        encoded_image = flat_pixels.reshape(pixels.shape)
        Image.fromarray(encoded_image).save(output_path)
        print(f"Imaginea a fost salvată la {output_path}")

    @staticmethod
    def decode_image(image_path, password):
        """
        Decodifică un mesaj ascuns într-o imagine folosind metoda LSB.

        :param image_path: Calea către imaginea codificată.
        :param password: Parola folosită pentru generarea unui seed pentru randomizare.
        :return: Datele decodificate (bytearray).
        """
        # Deschide imaginea codificată
        image = Image.open(image_path)
        pixels = np.array(image)

        # Setăm seed-ul pentru randomizare pe baza parolei
        random.seed(password)
        indices = list(range(pixels.size // 3))
        random.shuffle(indices)

        # Aplatizăm pixelii imaginii pentru a-i procesa mai ușor
        flat_pixels = pixels.flatten()
        binary_data = ""
        start_marker_binary = ''.join(format(byte, '08b') for byte in b"@START@")
        end_marker_binary = ''.join(format(byte, '08b') for byte in b"@END@")
        max_bits = 5000 * 8 * 3  # Numărul maxim de biți pentru 5000 caractere

        print(f"Max bits that can be read: {max_bits}")

        # Parcurgem fiecare pixel și extragem bitul cel mai puțin semnificativ
        for i in indices:
            if len(binary_data) + 3 > max_bits:
                print("Exceeded maximum number of readable bits.")
                break
            binary_data += str(flat_pixels[i * 3] & 1)
            binary_data += str(flat_pixels[i * 3 + 1] & 1)
            binary_data += str(flat_pixels[i * 3 + 2] & 1)

            # Verificăm dacă am atins delimitatorul de sfârșit
            if len(binary_data) >= len(end_marker_binary) and binary_data[
                                                              -len(end_marker_binary):] == end_marker_binary:
                binary_data = binary_data[:-len(end_marker_binary)]
                print("End marker found.")
                break

        print(f"Binary data length: {len(binary_data)}")

        # Convertim datele binare în bytes
        all_bytes = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
        decoded_data = bytearray([int(byte, 2) for byte in all_bytes])

        print(f"Decoded data length: {len(decoded_data)}")
        print(f"Decoded data: {decoded_data}")

        # Eliminăm delimitatorii de început și sfârșit
        start_marker = b'@START@'
        end_marker = b'@END@'

        start_index = decoded_data.find(start_marker)
        end_index = decoded_data.find(end_marker, start_index + len(start_marker))

        if start_index != -1 and end_index != -1:
            decoded_data = decoded_data[start_index + len(start_marker):end_index]
        else:
            raise ValueError("Delimitatorii nu au fost găsiți în mesajul decodat.")

        print(f"Final decoded data length: {len(decoded_data)}")
        print(f"Final decoded data: {decoded_data}")

        # Întoarcem datele decodificate, eliminând eventualele caractere '\x00'
        return decoded_data.rstrip(b'\x00')

    @staticmethod
    def calculate_hash(image_path):
        """
        Calculează hash-ul SHA-256 al unei imagini pentru a verifica integritatea acesteia.

        :param image_path: Calea către imagine.
        :return: Hash-ul calculat (string).
        """
        # Inițializăm obiectul hasher pentru SHA-256
        hasher = hashlib.sha256()

        # Deschidem imaginea în modul binar și calculăm hash-ul acesteia
        with open(image_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)

        # Returnăm hash-ul calculat ca un șir de caractere hexazecimal
        return hasher.hexdigest()
