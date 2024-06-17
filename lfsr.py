"""
Acest fișier implementează algoritmul LFSR (Linear Feedback Shift Register).
LFSR este utilizat pentru generarea unei secvențe de biți pseudo-aleatorii care pot fi folosiți pentru criptare.
Clasa principală este:
- `LFSR`: implementează funcționalitățile LFSR pentru generarea de biți și criptarea datelor.
"""

class LFSR:
    def __init__(self, seed, taps):
        """
        Initializează un LFSR cu un seed și o listă de taps.
        Seed-ul reprezintă starea inițială a registrului, iar taps reprezintă
        pozițiile din registru unde se va face feedback-ul.

        :param seed: Seed-ul inițial (număr întreg).
        :param taps: Lista de taps (pozițiile în care se face feedback).
        """
        # Setăm starea inițială a LFSR-ului
        self.state = seed
        # Setăm pozițiile de feedback
        self.taps = taps

    def next_bit(self):
        """
        Calculează următorul bit în secvența LFSR. Aceasta se face prin calculul
        XOR între bitii specificați de taps și bitul cel mai puțin semnificativ al stării curente.

        :return: Următorul bit (0 sau 1).
        """
        xor = 0
        # Calculăm XOR-ul pentru toți bitii specificați de taps
        for tap in self.taps:
            xor ^= (self.state >> tap) & 1
        # Shiftăm registrul la dreapta și adăugăm noul bit calculat la poziția cea mai semnificativă
        self.state = (self.state >> 1) | (xor << 63)  # Schimbăm 7 în 63 pentru a folosi un LFSR pe 64 de biți
        next_bit = self.state & 1
        return next_bit

    def encrypt(self, data):
        """
        Criptează datele folosind secvența generată de LFSR.
        Datele sunt criptate bit cu bit folosind secvența de biți generată de LFSR.

        :param data: Datele de criptat (bytearray).
        :return: Datele criptate (bytearray).
        """
        encrypted_data = bytearray(data)
        # Parcurgem fiecare byte din date
        for i in range(len(data)):
            # Parcurgem fiecare bit din byte
            for j in range(8):
                bit = self.next_bit()
                encrypted_data[i] ^= (bit << j)

        return encrypted_data
