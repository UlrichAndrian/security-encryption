import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from encryption_tool import encrypt_multi_layer, decrypt_multi_layer
import os

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
        self.mode_var = tk.StringVar(value="file")
        self.file_radio = ttk.Radiobutton(frame, text="File", variable=self.mode_var, value="file")
        self.file_radio.grid(row=0, column=1, pady=5, padx=5, sticky=tk.W)
        self.directory_radio = ttk.Radiobutton(frame, text="Directory", variable=self.mode_var, value="directory")
        self.directory_radio.grid(row=0, column=2, pady=5, padx=5, sticky=tk.W)

        # Input file selection
        self.input_label = ttk.Label(frame, text="Input File/Directory:")
        self.input_label.grid(row=1, column=0, pady=5, padx=5, sticky=tk.W)
        self.input_entry = ttk.Entry(frame, width=50)
        self.input_entry.grid(row=1, column=1, pady=5, padx=5, columnspan=2)
        self.input_button = ttk.Button(frame, text="Browse", command=self.browse_input_file)
        self.input_button.grid(row=1, column=3, pady=5, padx=5)

        # Output file selection
        self.output_label = ttk.Label(frame, text="Output File/Directory:")
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
        path = filedialog.askdirectory() if self.mode_var.get() == "directory" else filedialog.askopenfilename()
        if path:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, path)

    def browse_output_file(self):
        path = filedialog.askdirectory() if self.mode_var.get() == "directory" else filedialog.asksaveasfilename()
        if path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, path)

    def execute(self):
        mode = self.mode_var.get()
        input_path = self.input_entry.get()
        output_path = self.output_entry.get()
        password = self.password_entry.get()

        if mode == "directory":
            self.process_directory(input_path, output_path, password)
        else:
            self.process_file(input_path, output_path, password)

    def process_directory(self, input_dir, output_dir, password):
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                input_file = os.path.join(root, file)
                rel_path = os.path.relpath(input_file, input_dir)
                output_file = os.path.join(output_dir, rel_path)
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                self.process_file(input_file, output_file, password)

    def process_file(self, input_file, output_file, password):
        try:
            if self.mode_var.get() == "file" and self.file_radio['value'] == "encrypt":
                with open(input_file, "rb") as f:
                    data = f.read()
                encrypted_data = encrypt_multi_layer(data, password)
                with open(output_file, "wb") as f:
                    f.write(encrypted_data)
            elif self.mode_var.get() == "file" and self.file_radio['value'] == "decrypt":
                with open(input_file, "rb") as f:
                    encrypted_data = f.read()
                data = decrypt_multi_layer(encrypted_data, password)
                with open(output_file, "wb") as f:
                    f.write(data)
            self.status_label.config(text="Success", foreground="green")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}", foreground="red")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
