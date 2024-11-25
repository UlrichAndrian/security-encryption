import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from encryption_tool import encrypt_file, decrypt_file, derive_key_from_password
import tkinter.ttk as ttk
import shutil

# Function to encrypt a file
def encrypt_file_ui():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if file_path:
        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if password:
            key = derive_key_from_password(password, b'salt')  # Replace 'salt' with actual salt logic
            output_path = filedialog.asksaveasfilename(defaultextension=".enc", title="Save encrypted file as")
            if output_path:
                try:
                    encrypt_file(file_path, output_path, key=key)
                    messagebox.showinfo("Success", f"File encrypted successfully: {output_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to encrypt file: {e}")

# Function to decrypt a file
def decrypt_file_ui():
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if file_path:
        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if password:
            key = derive_key_from_password(password, b'salt')  # Replace 'salt' with actual salt logic
            output_path = filedialog.asksaveasfilename(defaultextension=".dec", title="Save decrypted file as")
            if output_path:
                try:
                    decrypt_file(file_path, output_path, key=key)
                    messagebox.showinfo("Success", f"File decrypted successfully: {output_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to decrypt file: {e}")

# Function to encrypt a directory and its contents
# Compress the directory first, then encrypt the compressed file
def encrypt_directory_ui():
    dir_path = filedialog.askdirectory(title="Select a directory to encrypt")
    if dir_path:
        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if password:
            key = derive_key_from_password(password, b'salt')  # Replace 'salt' with actual salt logic
            compressed_path = dir_path + '.zip'
            shutil.make_archive(dir_path, 'zip', dir_path)
            output_path = compressed_path + '.enc'
            try:
                encrypt_file(compressed_path, output_path, key=key)
                os.remove(compressed_path)  # Remove the compressed file after encryption
                shutil.rmtree(dir_path)  # Remove the original directory after encryption
                messagebox.showinfo("Success", f"Directory encrypted successfully: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to encrypt directory: {e}")

# Function to decrypt a directory and its contents
# Decrypt the file first, then decompress the contents
def decrypt_directory_ui():
    file_path = filedialog.askopenfilename(title="Select a directory to decrypt", filetypes=[("Encrypted files", "*.enc")])
    if file_path and file_path.endswith('.zip.enc'):
        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if password:
            key = derive_key_from_password(password, b'salt')  # Replace 'salt' with actual salt logic
            decrypted_path = file_path[:-4]  # Remove '.enc' extension
            try:
                decrypt_file(file_path, decrypted_path, key=key)
                shutil.unpack_archive(decrypted_path, decrypted_path[:-4])  # Unpack the zip file
                os.remove(decrypted_path)  # Remove the decrypted zip file
                messagebox.showinfo("Success", f"Directory decrypted successfully: {decrypted_path[:-4]}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt directory: {e}")

# Create the main application window
root = tk.Tk()
root.title("User-Friendly Encryption Tool")

# Variable to store the user's choice
choice_var = tk.StringVar(value='file')

# Function to update options based on user choice
def update_options():
    if choice_var.get() == 'file':
        # Show file options
        encrypt_button.config(command=encrypt_file_ui)
        decrypt_button.config(command=decrypt_file_ui)
    else:
        # Show directory options
        encrypt_button.config(command=encrypt_directory_ui)
        decrypt_button.config(command=decrypt_directory_ui)

# Radio buttons for choosing between file and directory
file_radio = ttk.Radiobutton(root, text='File', variable=choice_var, value='file', command=update_options)
dir_radio = ttk.Radiobutton(root, text='Directory', variable=choice_var, value='directory', command=update_options)
file_radio.pack(anchor=tk.W)
dir_radio.pack(anchor=tk.W)

# Buttons for encrypt and decrypt
encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_file_ui)
decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt_file_ui)
encrypt_button.pack(pady=10)
decrypt_button.pack(pady=10)

# Apply a modern style to the application
style = ttk.Style()
style.theme_use('clam')  # You can choose from available themes like 'clam', 'alt', 'default', etc.
style.configure('TButton', font=('Helvetica', 10), foreground='blue')
style.configure('TLabel', font=('Helvetica', 10), foreground='black')

# Update the main application window layout
root.geometry('500x300')

# Start the Tkinter event loop
root.mainloop()
