import json
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox


class PasswordManager:
    def __init__(self):
        self.passwords = {}

    def verify_password(self, password):
        lower = higher = symbol = num = False
        length = len(password) > 11

        for char in password:
            if char.islower(): lower = True
            if char.isupper(): higher = True
            if char.isnumeric(): num = True
            if not char.isalnum(): symbol = True

        errors_list = []
        if not length: errors_list.append("• Password should be at least 12 characters")
        if not lower: errors_list.append("• At least one lowercase letter required")
        if not higher: errors_list.append("• At least one uppercase letter required")
        if not num: errors_list.append("• At least one numeric digit required")
        if not symbol: errors_list.append("• At least one special character required")

        return len(errors_list) == 0, errors_list  # (T,errors_list) or (F,errors_list)

    def add_password(self, service, password):
        is_valid, errors_list = self.verify_password(password)
        if is_valid:
            self.passwords[service] = password[::-1]
            return True, f"Password for {service} added successfully!"

        return False, "\n".join(errors_list)

    def get_password(self, service):
        if service in self.passwords:
            return self.passwords[service][::-1], f"Password for {service}: {self.passwords[service][::-1]}"
        return None, "Password not found for this service"

    def change_password(self, service, new_password):
        if service not in self.passwords:
            return False, "Service not found"

        is_valid, errors_list = self.verify_password(new_password)
        if is_valid:
            self.passwords[service] = new_password[::-1]
            return True, f"Password for {service} changed successfully!"
        return False, "\n".join(errors_list)

    def save_to_file(self):
        try:
            with open("passwords.json", "w") as f:
                json.dump(self.passwords, f, indent=4)
            return True, "Passwords saved successfully!"
        except Exception as e:
            return False, f"Error saving passwords: {str(e)}"

    def load_from_file(self):
        try:
            with open("passwords.json", "r") as f:
                self.passwords = json.load(f)
            return True, "Passwords loaded successfully!"
        except FileNotFoundError:
            return False, "No existing password file found"
        except Exception as e:
            return False, f"Error loading passwords: {str(e)}"


class PasswordManagerGUI:
    def __init__(self, master):
        self.master = master
        self.pm = PasswordManager()

        master.title("Password Manager ")
        master.geometry("600x400")
        self.create_widgets()
        self.load_passwords()

    def create_widgets(self):
        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat")
        style.configure("TLabel", padding=6)

        main_frame = ttk.Frame(self.master)
        main_frame.pack(pady=20, padx=30, fill=tk.BOTH, expand=True)

        # Service Input
        ttk.Label(main_frame, text="Service:").grid(row=0, column=0, sticky=tk.W)
        self.service_entry = ttk.Entry(main_frame, width=35)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5)

        # Password Input
        ttk.Label(main_frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(main_frame, width=35, show="•")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)

        ttk.Button(btn_frame, text="Add Password", command=self.add_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Get Password", command=self.get_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Change Password", command=self.change_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Exit", command=self.exit).pack(side=tk.LEFT, padx=5)

        # Output Area
        self.output_area = scrolledtext.ScrolledText(main_frame, height=12, wrap=tk.WORD)
        self.output_area.grid(row=3, column=0, columnspan=2, pady=10, sticky=tk.EW)

        # # Disable manual editing
        # self.output_area.config(state="normal")

    def load_passwords(self):
        status, message = self.pm.load_from_file()
        self.output_area.insert(tk.END, message + "\n")

    def clear_entries(self):
        self.service_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def add_password(self):
        service = self.service_entry.get().strip()
        password = self.password_entry.get().strip()

        if not service or not password:
            messagebox.showwarning("Add Password-Input Error", "Both fields are required!")
            return

        success, message = self.pm.add_password(service, password)
        self.output_area.insert(tk.END, message + "\n\n")
        if success: self.clear_entries()

    def get_password(self):
        service = self.service_entry.get().strip()
        if not service:
            messagebox.showwarning("Input Error", "Please enter a service name")
            return

        password, message = self.pm.get_password(service)
        self.output_area.insert(tk.END, message + "\n")
        if password:
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)
        self.output_area.insert(tk.END, "\n")

    def change_password(self):  # Here
        service = self.service_entry.get().strip()
        new_password = self.password_entry.get().strip()

        if not service or not new_password:
            messagebox.showwarning("Input Error", "Both fields are required!")
            return

        success, message = self.pm.change_password(service, new_password)
        self.output_area.insert(tk.END, message + "\n\n")
        if success: self.clear_entries()

    def exit(self):
        status, message = self.pm.save_to_file()
        self.output_area.insert(tk.END, message + "\n")
        self.master.after(1000, self.master.destroy)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()
