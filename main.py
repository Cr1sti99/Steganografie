"""
Acest fișier implementează interfața grafică pentru aplicația de steganografie și criptare folosind LFSR.
Aplicația permite încărcarea unei imagini și a unui mesaj text, criptarea mesajului folosind LFSR,
ascunderea acestuia în imagine folosind steganografia și extragerea și decriptarea mesajului dintr-o imagine codificată.
"""

import tkinter as tk
from tkinter import filedialog, ttk
from PIL import Image, ImageTk
from lfsr import LFSR
from steganography import Steganography


# Funcție pentru încărcarea unei imagini
def upload_image(frame, img_label, result_label):
    """
    Permite utilizatorului să încarce o imagine din sistemul de fișiere.
    Imaginea este redimensionată și afișată în interfață.

    :param frame: Frame-ul în care se află eticheta pentru imagine.
    :param img_label: Eticheta în care va fi afișată imaginea.
    :param result_label: Eticheta în care se vor afișa rezultatele operațiunilor.
    """
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])
    if file_path:
        image = Image.open(file_path)
        image.thumbnail((300, 300))  # Redimensionăm imaginea pentru a fi vizibilă într-un spațiu limitat
        img_display = ImageTk.PhotoImage(image)
        img_label.config(image=img_display)
        img_label.image = img_display
        img_label.file_path = file_path


# Funcție pentru încărcarea unui mesaj
def upload_message():
    """
    Permite utilizatorului să încarce un mesaj text dintr-un fișier.
    Mesajul este afișat în câmpul de text din interfață.
    """
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            message = file.read()
            message_entry.delete(1.0, tk.END)
            message_entry.insert(tk.END, message)


# Funcție pentru a goli ecranul și a afișa un mesaj de succes
def clear_frame(frame):
    """
    Golește toate widget-urile dintr-un frame și afișează un mesaj de succes.

    :param frame: Frame-ul care va fi golit.
    """
    for widget in frame.winfo_children():
        widget.destroy()
    tk.Label(frame, text="Mesajul a fost criptat și, prin steganografie, a fost atașat imaginii cu succes").pack(
        pady=20)


# Funcție pentru criptarea mesajului și inserarea acestuia în imagine
def encrypt_message():
    """
    Criptează un mesaj text folosind LFSR și îl inserează într-o imagine folosind steganografia.
    Afișează mesaje de eroare sau succes în funcție de rezultatul operațiunii.
    """
    try:
        if not verify_inputs():
            return

        image_path = img_label_encrypt.file_path
        message = message_entry.get(1.0, tk.END).strip()

        # Limităm mesajul la 5000 de caractere
        if len(message) > 5000:
            result_label.config(text="Mesajul este prea lung. Maximul permis este de 5000 de caractere.")
            return

        # Adăugăm delimitatorii @START@ și @END@
        original_message = message
        message = f"@START@{message}@END@"
        message = message.encode('utf-8')

        seed = seed_entry.get().strip()

        # Utilizăm seed-ul ca un șir de caractere direct pentru LFSR
        seed_value = sum([ord(c) for c in seed])  # Convertim seed-ul într-un număr

        # Setăm taps-urile pentru LFSR
        taps = [0, 1, 3, 12]

        # Inițializăm LFSR-ul cu seed-ul și taps-urile
        lfsr = LFSR(seed_value, taps)
        encrypted_message = lfsr.encrypt(message)

        # Afișăm mesajul criptat în formă hex pentru depanare
        print(f"Mesaj criptat (hex): {encrypted_message.hex()}")
        print(f"Lungimea mesajului criptat: {len(encrypted_message)}")

        # Codificăm mesajul criptat în imagine folosind metoda LSB
        output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if output_image_path:
            Steganography.encode_image(image_path, encrypted_message, output_image_path, seed)
            hash_value = Steganography.calculate_hash(output_image_path)

            # Salvăm hash-ul
            with open(f"{output_image_path}.hash", 'w') as hash_file:
                hash_file.write(hash_value)

            clear_frame(frame_encrypt)
        else:
            result_label.config(text="Salvarea imaginii a fost anulată.")
    except Exception as e:
        result_label.config(text=f"A apărut o eroare: {str(e)}")


# Funcție pentru verificarea hash-ului imaginii
def verify_hash():
    """
    Verifică integritatea unei imagini codificate prin compararea hash-ului acesteia cu un hash salvat anterior.
    Afișează mesaje de eroare sau succes în funcție de rezultatul comparației.
    """
    try:
        if not hasattr(img_label_decrypt, 'file_path'):
            result_label_decrypt.config(text="Nicio imagine încărcată.")
            return

        image_hash = Steganography.calculate_hash(img_label_decrypt.file_path)
        hash_path = filedialog.askopenfilename(filetypes=[("Text files", "*.hash")])
        if not hash_path:
            result_label_decrypt.config(text="Niciun hash încărcat pentru comparație.")
            return

        with open(hash_path, 'r', encoding='utf-8') as file:
            expected_hash = file.read().strip()

        if image_hash == expected_hash:
            result_label_decrypt.config(text="Hash-urile coincid. Puteți extrage mesajul.")
        else:
            result_label_decrypt.config(text="Este posibil ca mesajul sa fi fost corupt!!!Hash-urile nu coincid. Verificați imaginea și hash-ul. ")
    except Exception as e:
        result_label_decrypt.config(text=f"A apărut o eroare: {str(e)}")


# Funcție pentru extragerea mesajului și decriptarea acestuia
def extract_message():
    """
    Extrage un mesaj criptat dintr-o imagine folosind steganografia și îl decriptează folosind LFSR.
    Afișează mesajul decriptat într-o fereastră nouă și permite salvarea acestuia într-un fișier text.
    """
    try:
        if not hasattr(img_label_decrypt, 'file_path'):
            result_label_decrypt.config(text="Nicio imagine încărcată.")
            return

        image_path = img_label_decrypt.file_path

        # Decodificăm mesajul din imagine folosind metoda LSB
        seed = seed_entry_decrypt.get().strip()
        result_label_decrypt.config(text="Extragerea mesajului...")
        encrypted_message = Steganography.decode_image(image_path, seed)

        result_label_decrypt.config(text="Mesaj extras cu succes. Decriptarea mesajului...")

        # Decriptăm mesajul folosind LFSR
        seed_value = sum([ord(c) for c in seed])  # Convertim seed-ul într-un număr

        # Setăm taps-urile pentru LFSR
        taps = [0, 1, 3, 12]

        # Inițializăm LFSR-ul cu seed-ul și taps-urile
        lfsr = LFSR(seed_value, taps)
        decrypted_message = lfsr.encrypt(encrypted_message)

        # Afișăm mesajul decriptat în formă hex pentru depanare
        print(f"Mesaj decriptat (hex): {decrypted_message.hex()}")
        print(f"Lungimea mesajului decriptat: {len(decrypted_message)}")

        # Afișăm mesajul într-o minifereastră
        try:
            decrypted_message = decrypted_message.decode('utf-8')  # Utilizăm 'utf-8' pentru decodificare
        except UnicodeDecodeError:
            result_label_decrypt.config(text="A apărut o eroare la decodificarea mesajului. Format invalid.")
            return

        show_message_window(decrypted_message)

        # Salvăm mesajul într-un fișier
        save_message_to_file(decrypted_message)
    except Exception as e:
        result_label_decrypt.config(text=f"A apărut o eroare: {str(e)}")


# Funcție pentru afișarea mesajului într-o fereastră nouă
def show_message_window(message):
    """
    Afișează mesajul extras și decriptat într-o fereastră nouă.

    :param message: Mesajul de afișat.
    """
    window = tk.Toplevel(root)
    window.title("Mesaj Extras")
    tk.Label(window, text="Mesajul extras:").pack(pady=5)
    message_text = tk.Text(window, height=10, width=50)
    message_text.pack(pady=5)
    message_text.insert(tk.END, message)
    message_text.config(state=tk.DISABLED)


# Funcție pentru salvarea mesajului într-un fișier
def save_message_to_file(message):
    """
    Salvează mesajul extras și decriptat într-un fișier text.

    :param message: Mesajul de salvat.
    """
    save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if save_path:
        with open(save_path, 'w', encoding='utf-8') as file:
            file.write(message)


# Funcție pentru verificarea input-ului
def verify_inputs():
    """
    Verifică dacă toate input-urile necesare sunt specificate.
    Afișează mesaje de eroare în cazul în care un input este lipsă.

    :return: True dacă toate input-urile sunt specifice, False în caz contrar.
    """
    if not hasattr(img_label_encrypt, 'file_path'):
        result_label.config(text="Nicio imagine încărcată.")
        return False

    message = message_entry.get(1.0, tk.END).strip()
    seed = seed_entry.get().strip()

    if not message:
        result_label.config(text="Mesajul nu este specificat.")
        return False

    if not seed:
        result_label.config(text="Seed-ul nu este specificat.")
        return False

    return True


# Inițializarea interfeței grafice
root = tk.Tk()
root.title(" Aplicatie Steganografie")

# Crearea unui notebook pentru a împărți interfața în două ecrane
notebook = ttk.Notebook(root)
notebook.pack(expand=1, fill="both")

# Crearea primului ecran pentru criptare
frame_encrypt = tk.Frame(notebook)
notebook.add(frame_encrypt, text="Criptare")

frame_encrypt_title = tk.Label(frame_encrypt, text="Criptare Mesaj și Inserare in Imagine, prin Steganografie", font=("Helvetica", 16))
frame_encrypt_title.pack(pady=10)

upload_button = tk.Button(frame_encrypt, text="Încarcă Imagine",
                          command=lambda: upload_image(frame_encrypt, img_label_encrypt, result_label))
upload_button.pack(pady=5)

upload_message_button = tk.Button(frame_encrypt, text="Încarcă Mesaj", command=upload_message)
upload_message_button.pack(pady=5)

message_label = tk.Label(frame_encrypt, text="Mesaj:")
message_label.pack(pady=5)
message_entry = tk.Text(frame_encrypt, height=10, width=50)
message_entry.pack(pady=5)

seed_label = tk.Label(frame_encrypt, text="Introdu un seed pentru LFSR:")
seed_label.pack(pady=5)
seed_entry = tk.Entry(frame_encrypt, width=50, show="*")  # Câmp de tip parolă
seed_entry.pack(pady=5)

encrypt_button = tk.Button(frame_encrypt, text="Criptează și Inserează Mesaj", command=encrypt_message)
encrypt_button.pack(pady=10)

result_label = tk.Label(frame_encrypt, text="", wraplength=400)
result_label.pack(pady=5)

img_label_encrypt = tk.Label(frame_encrypt)
img_label_encrypt.pack(pady=10)

# Crearea celui de-al doilea ecran pentru decriptare
frame_decrypt = tk.Frame(notebook)
notebook.add(frame_decrypt, text="Decriptare")

frame_decrypt_title = tk.Label(frame_decrypt, text="Extragere și Decriptare Mesaj", font=("Helvetica", 16))
frame_decrypt_title.pack(pady=10)

upload_button_decrypt = tk.Button(frame_decrypt, text="Încarcă Imagine",
                                  command=lambda: upload_image(frame_decrypt, img_label_decrypt, result_label_decrypt))
upload_button_decrypt.pack(pady=5)

verify_hash_button = tk.Button(frame_decrypt, text="Încarcă și Verifică Hash", command=verify_hash)
verify_hash_button.pack(pady=5)

seed_label_decrypt = tk.Label(frame_decrypt, text="Alege un seed pentru LFSR:")
seed_label_decrypt.pack(pady=5)
seed_entry_decrypt = tk.Entry(frame_decrypt, width=50, show="*")  # Câmp de tip parolă
seed_entry_decrypt.pack(pady=5)

extract_button = tk.Button(frame_decrypt, text="Extrage Mesaj", command=extract_message)
extract_button.pack(pady=10)

img_label_decrypt = tk.Label(frame_decrypt)
img_label_decrypt.pack(pady=10)

result_label_decrypt = tk.Label(frame_decrypt, text="", wraplength=400)
result_label_decrypt.pack(pady=5)

# Pornim bucla principală a interfeței grafice
root.mainloop()
