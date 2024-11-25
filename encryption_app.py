import tkinter as tk
from tkinter import filedialog, messagebox
from encryption_tool import encrypt_file, decrypt_file

# Function to encrypt a file
def encrypt_file_ui():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if file_path:
        output_path = filedialog.asksaveasfilename(defaultextension=".enc", title="Save encrypted file as")
        if output_path:
            try:
                encrypt_file(file_path, output_path, key=b'some_key')  # Replace with actual key logic
                messagebox.showinfo("Success", f"File encrypted successfully: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to encrypt file: {e}")

# Function to decrypt a file
def decrypt_file_ui():
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if file_path:
        output_path = filedialog.asksaveasfilename(defaultextension=".dec", title="Save decrypted file as")
        if output_path:
            try:
                decrypt_file(file_path, output_path, key=b'some_key')  # Replace with actual key logic
                messagebox.showinfo("Success", f"File decrypted successfully: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt file: {e}")

# Create the main application window
root = tk.Tk()
root.title("Encryption Tool")

# Create buttons for encryption and decryption
encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_file_ui)
decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file_ui)

# Place buttons in the window
encrypt_button.pack(pady=10)
decrypt_button.pack(pady=10)

# Start the Tkinter event loop
root.mainloop()
