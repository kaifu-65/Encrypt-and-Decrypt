import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from ciphers import *
from hash_functions import *
from login_signup import *
from utils import LinkedList

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("cryptography")
        self.geometry("800x600")
        self.configure(bg='grey17')
        self.username = None
        self.history = LinkedList()
        self.style = ttk.Style()
        self.style.configure('TFrame', background='grey17')
        self.style.configure('TButton', font=("Arial", 14), background='black', foreground='black')
        self.style.configure('TLabel', background='grey17', foreground='white', font=("Arial", 14))
        self.style.configure('TEntry', font=("Arial", 14), background='white', foreground='black')
        self.home_page()

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def center_container(self, container):
        container.pack(expand=True, padx=20, pady=20)

    def home_page(self):
        self.clear_screen()
        container = ttk.Frame(self)
        self.center_container(container)
        ttk.Label(container, text="Welcome", font=("Arial", 24)).pack(pady=20)
        ttk.Button(container, text="Login", command=self.login_screen, width=20).pack(pady=10)
        ttk.Button(container, text="Sign Up", command=self.signup_screen, width=20).pack(pady=10)

    def login_screen(self):
        self.clear_screen()
        container = ttk.Frame(self)
        self.center_container(container)
        ttk.Label(container, text="Login", font=("Arial", 24)).pack(pady=20)
        ttk.Label(container, text="Username").pack(pady=5)
        username_entry = ttk.Entry(container, font=("Arial", 14))
        username_entry.pack(pady=5)
        ttk.Label(container, text="Password").pack(pady=5)
        password_entry = ttk.Entry(container, font=("Arial", 14), show="*")
        password_entry.pack(pady=5)
        ttk.Button(container, text="Login", command=lambda: self.login_action(username_entry.get(), password_entry.get()), width=20).pack(pady=20)
        ttk.Button(container, text="Back", command=self.home_page, width=20).pack(pady=10)

    def signup_screen(self):
        self.clear_screen()
        container = ttk.Frame(self)
        self.center_container(container)
        ttk.Label(container, text="Sign Up", font=("Arial", 24)).pack(pady=20)
        ttk.Label(container, text="Username").pack(pady=5)
        username_entry = ttk.Entry(container, font=("Arial", 14))
        username_entry.pack(pady=5)
        ttk.Label(container, text="Password").pack(pady=5)
        password_entry = ttk.Entry(container, font=("Arial", 14), show="*")
        password_entry.pack(pady=5)

        ttk.Label(container, text="Confirm Password").pack(pady=5)
        password_entry2 = ttk.Entry(container, font=("Arial", 14), show="*")
        password_entry2.pack(pady=5)



        ttk.Button(container, text="Sign Up", command=lambda: self.signup_action(username_entry.get(), password_entry.get(),password_entry2.get()), width=20).pack(pady=20)
        ttk.Button(container, text="Back", command=self.home_page, width=20).pack(pady=10)

    def create_scrollable_frame(self, parent):
        container = ttk.Frame(parent)
        container.pack(expand=True, fill='both')
        canvas = tk.Canvas(container, bg='grey17', highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        return scrollable_frame

    def user_dashboard(self):
        self.clear_screen()
        container = ttk.Frame(self)
        self.center_container(container)
        ttk.Label(container, text=f"Welcome, {self.username}", font=("Arial", 24)).pack(pady=20)
        ttk.Button(container, text="Encrypt/Decrypt", command=self.cipher_options, width=20).pack(pady=10)
        ttk.Button(container, text="Hash", command=self.hash_options, width=20).pack(pady=10)
        ttk.Button(container, text="View History", command=self.show_history, width=20).pack(pady=10)
        ttk.Button(container, text="Logout", command=self.logout, width=20).pack(pady=10)

    def cipher_options(self):
        self.clear_screen()
        frame = self.create_scrollable_frame(self)
        
        ttk.Label(frame, text="Cipher Options", font=("Arial", 24)).pack(pady=20)
        ttk.Label(frame, text="Message").pack(pady=10)
        message_entry = ttk.Entry(frame, font=("Arial", 14), width=50)
        message_entry.pack(pady=5)
        ttk.Label(frame, text="Key").pack(pady=10)
        key_entry = ttk.Entry(frame, font=("Arial", 14), width=50)
        key_entry.pack(pady=5)

        ttk.Button(frame, text="Encrypt with Caesar Cipher", command=lambda: self.cipher_action('caesar', message_entry.get(), key_entry.get(), True), width=30).pack(pady=5)
        ttk.Button(frame, text="Decrypt with Caesar Cipher", command=lambda: self.cipher_action('caesar', message_entry.get(), key_entry.get(), False), width=30).pack(pady=5)
        
        ttk.Button(frame, text="Encrypt with Vigenere Cipher", command=lambda: self.cipher_action('vigenere', message_entry.get(), key_entry.get(), True), width=30).pack(pady=5)
        ttk.Button(frame, text="Decrypt with Vigenere Cipher", command=lambda: self.cipher_action('vigenere', message_entry.get(), key_entry.get(), False), width=30).pack(pady=5)

        ttk.Button(frame, text="Encrypt with Affine Cipher", command=lambda: self.cipher_action('affine', message_entry.get(), key_entry.get(), True), width=30).pack(pady=5)
        ttk.Button(frame, text="Decrypt with Affine Cipher", command=lambda: self.cipher_action('affine', message_entry.get(), key_entry.get(), False), width=30).pack(pady=5)

        ttk.Button(frame, text="Encrypt with AES", command=lambda: self.cipher_action('aes', message_entry.get(), key_entry.get(), True), width=30).pack(pady=5)
        ttk.Button(frame, text="Decrypt with AES", command=lambda: self.cipher_action('aes', message_entry.get(), key_entry.get(), False), width=30).pack(pady=5)

        ttk.Button(frame, text="Encrypt with DES", command=lambda: self.cipher_action('des', message_entry.get(), key_entry.get(), True), width=30).pack(pady=5)
        ttk.Button(frame, text="Decrypt with DES", command=lambda: self.cipher_action('des', message_entry.get(), key_entry.get(), False), width=30).pack(pady=5)

        ttk.Button(frame, text="Back", command=self.user_dashboard, width=20).pack(pady=10)

    def hash_options(self):
        self.clear_screen()
        frame = self.create_scrollable_frame(self)

        ttk.Label(frame, text="Hash Options", font=("Arial", 24)).pack(pady=20)
        ttk.Label(frame, text="Message").pack(pady=5)
        hash_message_entry = ttk.Entry(frame, font=("Arial", 14), width=50)
        hash_message_entry.pack(pady=5)

        ttk.Button(frame, text="MD5 Hash", command=lambda: self.hash_action('md5', hash_message_entry.get()), width=30).pack(pady=5)
        ttk.Button(frame, text="SHA1 Hash", command=lambda: self.hash_action('sha1', hash_message_entry.get()), width=30).pack(pady=5)

        ttk.Button(frame, text="Back", command=self.user_dashboard, width=20).pack(pady=10)

    def cipher_action(self, cipher_type, message, key, encrypt=True):
        if cipher_type == 'caesar':
            result = caesar_cipher(message, int(key), encrypt)
        elif cipher_type == 'vigenere':
            result = vigenere_cipher(message, key, encrypt)
        elif cipher_type == 'affine':
            a, b = map(int, key.split(','))
            result = affine_cipher(message, a, b, encrypt)
        elif cipher_type == 'aes':
            result = aes_encrypt(message, key) if encrypt else aes_decrypt(message, key)
        elif cipher_type == 'des':
            result = des_encrypt(message, key) if encrypt else des_decrypt(message, key)
        messagebox.showinfo("Result", f"Result: {result}")
        save_history(self.username, 'cipher', cipher_type, message, key, result)

    def hash_action(self, hash_type, message):
        if hash_type == 'md5':
            result = md5_hash(message)
        elif hash_type == 'sha1':
            result = sha1_hash(message)
        messagebox.showinfo("Result", f"Hash: {result}")
        save_history(self.username, 'hash', hash_type, message, None, result)

    def show_history(self):
        self.clear_screen()
        container = ttk.Frame(self)
        self.center_container(container)
        ttk.Label(container, text=f"History for {self.username}", font=("Arial", 24)).pack(pady=20)
        history_list = get_history(self.username)
        history_text = scrolledtext.ScrolledText(container, width=80, height=20, font=("Arial", 12), bg='grey17', fg='white', insertbackground='white')
        for record in history_list:
            history_text.insert(tk.END, f"Action: {record[2]}, Mode: {record[3]}, Message: {record[4]}, Key: {record[5]}, Output: {record[6]}, Timestamp: {record[7]}\n\n")
        history_text.pack(pady=10)
        ttk.Button(container, text="Back", command=self.user_dashboard, width=20).pack(pady=10)

    def login_action(self, username, password):
        user = login(username, password)
        if user:
            self.username = username
            messagebox.showinfo("Login Success", f"Welcome {username}!")
            self.user_dashboard()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def signup_action(self, username, password,password2):
        if password != password2:
            messagebox.showerror("Sign Up Failed", "Both passwords must be same")
            return

        if signup(username, password):
            messagebox.showinfo("Sign Up Success", "Account created successfully!")
            self.home_page()
        else:
            messagebox.showerror("Sign Up Failed", "Username already exists")

    def logout(self):
        self.username = None
        self.home_page()

    def run(self):
        self.mainloop()

if __name__ == "__main__":
    app = Application()
    app.run()
