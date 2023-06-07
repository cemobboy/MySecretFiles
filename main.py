from tkinter import *
from tkinter import messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import CryptographyUnsupportedAlgorithm
from cryptography.fernet import Fernet
import base64

window = Tk()
window.title("Top Secret")
window.minsize(height=0, width=100)
window.config(padx=75, pady=75)

photo =PhotoImage(file='topsecret.png')
photo_label = Label(image=photo)
photo_label.pack()




enter_title_label = Label(text="Başlık", font=("Arial", 10, "bold"))
enter_title_label.config(padx=10, pady=5)
enter_title_label.pack()

enter_title_entry = Entry(width=30)
enter_title_entry.pack()

enter_secret_text_label = Label(text="Şifrelenecek kelime", font=("Arial", 10, "bold"))
enter_secret_text_label.config(padx=10, pady=5)
enter_secret_text_label.pack()

enter_secret_text = Text(width=30, height=10)
enter_secret_text.pack()

enter_master_key_label = Label(text="Anahtar kelime", font=("Arial", 10, "bold"))
enter_master_key_label.config(padx=10, pady=10)
enter_master_key_label.pack()

enter_master_key_entry = Entry(width=30)
enter_master_key_entry.pack()


def generate_key(master_key):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=100000,
    )
    try:
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return key
    except CryptographyUnsupportedAlgorithm:
        messagebox.showerror("Hata", "Bu işletim sistemi algoritmasını desteklemiyor.")
        return None


def save_and_encrypt():
    title = enter_title_entry.get()
    message = enter_secret_text.get("1.0", END).strip()
    master_key = enter_master_key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Hata", message="Boş alanları doldurun")
    else:
        key = generate_key(master_key)
        if key:
            try:
                f = Fernet(key)
                encrypted_message = f.encrypt(message.encode("utf-8"))
                with open('Mysecret.txt', 'a', encoding="utf-8") as file:
                    file.write('Başlık isimi: ' + title + '\n')
                    file.write('Şifreli mesaj: ' + encrypted_message.decode() + '\n')
                    file.write("-" * 500 + "\n")
            except Exception as e:
                messagebox.showerror("Hata", str(e))
            finally:
                enter_title_entry.delete(0, END)
                enter_secret_text.delete('1.0', END)
                enter_master_key_entry.delete(0, END)


def decrypt_message():
    title = enter_title_entry.get()
    master_key = enter_master_key_entry.get()
    encrypted_message = enter_secret_text.get("1.0", END).strip()

    if len(title) != 0 or len(master_key) == 0 or len(encrypted_message) == 0:
        messagebox.showinfo(title="Hata", message="Lütfen anahtar ve şifreli metni girin")
    else:
        key = generate_key(master_key)
        if key:
            try:
                f = Fernet(key)
                decrypted_message = f.decrypt(encrypted_message.encode()).decode("utf-8")
                messagebox.showinfo(title="Çözülen mesaj", message=decrypted_message)
            except Exception as e:
                messagebox.showinfo("Hata", 'Lütfen anahtar kelimeyi düzgün yazıldığından emin olun')


save_encrypt = Button(text="Save & Encrypt", command=save_and_encrypt)
save_encrypt.pack()

decrypt = Button(text="Decrypt", command=decrypt_message)
decrypt.pack()

window.mainloop()
