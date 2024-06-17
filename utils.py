"""
Acest fișier conține funcții auxiliare pentru generarea seed-ului și calcularea hash-ului.
Funcțiile sunt utilizate pentru securizarea seed-ului pentru LFSR și pentru verificarea integrității imaginii.
"""

import hashlib
import os


def generate_seed(password, salt=None):
    """
    Generează un seed sigur folosind parola și un salt opțional.

    :param password: Parola utilizată pentru generarea seed-ului.
    :param salt: Salt-ul utilizat pentru generarea seed-ului (opțional).
    :return: Seed-ul generat (număr întreg) și salt-ul utilizat (bytes).
    """
    if salt is None:
        salt = os.urandom(16)  # Generăm un salt de 16 octeți dacă nu este furnizat
    password_salt = password.encode() + salt  # Combinăm parola și salt-ul
    seed = hashlib.sha256(password_salt).digest()  # Calculăm hash-ul SHA-256 al combinației
    seed = int.from_bytes(seed, 'big') & 0xFFFFFFFFFFFFFFFF  # Convertim hash-ul într-un număr de 64 de biți
    return seed, salt  # Returnăm seed-ul și salt-ul utilizat


def calculate_hash(image_path):
    """
    Calculează hash-ul SHA-256 al unei imagini.

    :param image_path: Calea către imagine.
    :return: Hash-ul calculat (string).
    """
    hasher = hashlib.sha256()  # Inițializăm obiectul hasher pentru SHA-256
    with open(image_path, 'rb') as f:
        buf = f.read()  # Citim conținutul imaginii în mod binar
        hasher.update(buf)  # Actualizăm hash-ul cu conținutul imaginii
    return hasher.hexdigest()  # Returnăm hash-ul calculat ca un șir de caractere hexazecimal
