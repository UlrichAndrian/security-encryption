import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from encryption_tool import encrypt_multi_layer, decrypt_multi_layer

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Encryption Tool")
        self.root.geometry('600x400')

        # Apply a modern style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Helvetica', 10), foreground='blue')
        style.configure('TLabel', font=('Helvetica', 10), foreground='black')

        # Create main frame
        frame = ttk.Frame(root, padding='10')
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Mode selection
        self.mode_label = ttk.Label(frame, text="Mode:")
        self.mode_label.grid(row=0, column=0, pady=5, padx=5, sticky=tk.W)
        self.mode_var = tk.StringVar(value="encrypt")
        self.encrypt_radio = ttk.Radiobutton(frame, text="Encrypt", variable=self.mode_var, value="encrypt")
        self.encrypt_radio.grid(row=0, column=1, pady=5, padx=5, sticky=tk.W)
        self.decrypt_radio = ttk.Radiobutton(frame, text="Decrypt", variable=self.mode_var, value="decrypt")
        self.decrypt_radio.grid(row=0, column=2, pady=5, padx=5, sticky=tk.W)

        # Input file selection
        self.input_label = ttk.Label(frame, text="Input File/Directory:")
        self.input_label.grid(row=1, column=0, pady=5, padx=5, sticky=tk.W)
        self.input_entry = ttk.Entry(frame, width=50)
        self.input_entry.grid(row=1, column=1, pady=5, padx=5, columnspan=2)
        self.input_button = ttk.Button(frame, text="Browse", command=self.browse_input_file)
        self.input_button.grid(row=1, column=3, pady=5, padx=5)

        # Output file selection
        self.output_label = ttk.Label(frame, text="Output File:")
        self.output_label.grid(row=2, column=0, pady=5, padx=5, sticky=tk.W)
        self.output_entry = ttk.Entry(frame, width=50)
        self.output_entry.grid(row=2, column=1, pady=5, padx=5, columnspan=2)
        self.output_button = ttk.Button(frame, text="Browse", command=self.browse_output_file)
        self.output_button.grid(row=2, column=3, pady=5, padx=5)

        # Password entry
        self.password_label = ttk.Label(frame, text="Password:")
        self.password_label.grid(row=3, column=0, pady=5, padx=5, sticky=tk.W)
        self.password_entry = ttk.Entry(frame, show="*", width=50)
        self.password_entry.grid(row=3, column=1, pady=5, padx=5, columnspan=2)

        # Execute button
        self.execute_button = ttk.Button(frame, text="Execute", command=self.execute)
        self.execute_button.grid(row=4, column=1, pady=20, padx=5)

        # Status label
        self.status_label = ttk.Label(frame, text="", foreground="red")
        self.status_label.grid(row=5, column=0, columnspan=4, pady=5, padx=5)

    def browse_input_file(self):
        if self.mode_var.get() == "encrypt":
            filename = filedialog.askopenfilename(title="Select a file or directory to encrypt")
            if not filename:
                filename = filedialog.askdirectory(title="Select a directory to encrypt")
        else:
            filename = filedialog.askopenfilename(title="Select a file or directory to decrypt")
            if not filename:
                filename = filedialog.askdirectory(title="Select a directory to decrypt")
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, filename)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename()
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, filename)

    def execute(self):
        mode = self.mode_var.get()
        input_file = self.input_entry.get()
        output_file = self.output_entry.get()
        password = self.password_entry.get()
        
        try:
            if mode == 'encrypt':
                if input_file.endswith('/'):
                    # Encrypt directory
                    import os
                    for root, dirs, files in os.walk(input_file):
                        for file in files:
                            file_path = os.path.join(root, file)
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            encrypted_data = encrypt_multi_layer(data, password)
                            with open(file_path, 'wb') as f:
                                f.write(encrypted_data)
                else:
                    # Encrypt file
                    with open(input_file, 'rb') as f:
                        data = f.read()
                    encrypted_data = encrypt_multi_layer(data, password)
                    with open(output_file, 'wb') as f:
                        f.write(encrypted_data)
                messagebox.showinfo("Success", f"File encrypted to {output_file}.")
            elif mode == 'decrypt':
                if input_file.endswith('/'):
                    # Decrypt directory
                    import os
                    for root, dirs, files in os.walk(input_file):
                        for file in files:
                            file_path = os.path.join(root, file)
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            decrypted_data = decrypt_multi_layer(data, password)
                            with open(file_path, 'wb') as f:
                                f.write(decrypted_data)
                else:
                    # Decrypt file
                    with open(input_file, 'rb') as f:
                        data = f.read()
                    decrypted_data = decrypt_multi_layer(data, password)
                    with open(output_file, 'wb') as f:
                        f.write(decrypted_data)
                messagebox.showinfo("Success", f"File decrypted to {output_file}.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
