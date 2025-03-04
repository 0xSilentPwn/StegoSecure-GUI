import cv2
import os
import tkinter as tk
from tkinter import filedialog, messagebox

# Character mappings
char_to_num = {chr(i): i for i in range(255)}
num_to_char = {i: chr(i) for i in range(255)}

# Function to encrypt an image
def encrypt_image(image_path, message, secret_key):
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not read the image.")
        return

    n, m, z = 0, 0, 0

    # Store the message length in the first pixel
    img[n, m, z] = len(message)
    m += 1  # Move to the next pixel
    hidden_data = encrypt_message("Secret Data")

    # Store the Secret Key in the image
    for char in secret_key:
        img[n, m, z] = char_to_num.get(char, 32)  # Store ASCII values
        n += 1
        m += 1
        z = (z + 1) % 3

    # Store the message in the image
    for char in message:
        img[n, m, z] = char_to_num.get(char, 32)  # Store ASCII values
        n += 1
        m += 1
        z = (z + 1) % 3
        extracted_data = steganography_extract_function("image.png")

    output_path = "encryptedImage.png"
    cv2.imwrite(output_path, img)
    messagebox.showinfo("Success", f"Message encrypted and saved as '{output_path}'")
    os.system(f"start {output_path}")  # Open the encrypted image

# Function to decrypt an image
def decrypt_image(image_path, entered_key):
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not read the image.")
        return

    n, m, z = 0, 0, 0
    original_message = decrypt_message(extracted_data)
    print("Decrypted Message:", original_message)

    # Retrieve message length
    message_length = img[n, m, z]
    m += 1  # Move to the next pixel

    # Retrieve stored Secret Key
    extracted_key = ""
    for _ in range(len(entered_key)):  # Assume the key length is known
        extracted_key += num_to_char.get(img[n, m, z], "?")
        n += 1
        m += 1
        z = (z + 1) % 3

    # Check if entered key matches the stored key
    if extracted_key != entered_key:
        messagebox.showerror("Error", "Invalid Secret Key! Decryption failed.")
        return

    # Extract the message
    extracted_message = ""
    for _ in range(message_length):
        extracted_message += num_to_char.get(img[n, m, z], "?")
        n += 1
        m += 1
        z = (z + 1) % 3

    messagebox.showinfo("Decryption Successful", f"Message: {extracted_message}")

# Function to hide a file inside an image
def encrypt_image_with_file(image_path, file_path, output_path="encryptedImage.png"):
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not read the image.")
        return

    # Get total available pixels in the image
    total_pixels = img.shape[0] * img.shape[1] * 3  # Height * Width * 3 (RGB channels)

    # Read file data as bytes
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Convert file data to binary
    binary_data = ''.join(format(byte, '08b') for byte in file_data)
    file_size = len(binary_data)

    # Check if file size fits in the image
    if file_size + 16 > total_pixels:  # +16 for storing file size
        messagebox.showerror("Error", "File too large for this image! Use a bigger image.")
        return

    n, m, z = 0, 0, 0

    # Store file size in the first few pixels (16 bits)
    img[n, m, z] = file_size & 255  # First byte
    img[n, m + 1, z] = (file_size >> 8) & 255  # Second byte
    m += 2

    # Embed file data in image pixels
    for bit in binary_data:
        img[n, m, z] = (img[n, m, z] & ~1) | int(bit)  # Modify LSB
        n += 1
        if n >= img.shape[0]:  # Move to next row
            n = 0
            m += 1
            if m >= img.shape[1]:  # If end of row, move to next channel
                m = 0
                z = (z + 1) % 3
                if z >= 3:
                    messagebox.showerror("Error", "Unexpected overflow while hiding data.")
                    return

    cv2.imwrite(output_path, img)
    messagebox.showinfo("Success", f"File hidden successfully in {output_path}")


# Function to extract a hidden file from an image
def decrypt_file_from_image(image_path, output_file="extracted_file.bin"):
    img = cv2.imread(image_path)
    if img is None:
        messagebox.showerror("Error", "Could not read the image.")
        return

    n, m, z = 0, 0, 0

    # Extract file size from the first two pixels (16 bits)
    file_size = img[n, m, z] | (img[n, m + 1, z] << 8)
    m += 2

    total_pixels = img.shape[0] * img.shape[1] * 3  # Total available bits

    # Validate if file size fits within the image
    if file_size > total_pixels:
        messagebox.showerror("Error", "File size is too large for this image! Decryption failed.")
        return

    binary_data = ""

    for _ in range(file_size):
        binary_data += str(img[n, m, z] & 1)  # Extract LSB
        n += 1
        if n >= img.shape[0]:  # Move to next row
            n = 0
            m += 1
            if m >= img.shape[1]:  # If end of row, move to next channel
                m = 0
                z = (z + 1) % 3
                if z >= 3:
                    messagebox.showerror("Error", "Unexpected overflow while extracting data.")
                    return

    # Convert binary data back to bytes
    file_data = bytearray(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))

    with open(output_file, "wb") as f:
        f.write(file_data)

    messagebox.showinfo("Success", f"File extracted successfully as {output_file}")
    
# Encryption Window
def open_encryption_window():
    enc_win = tk.Toplevel(root)
    enc_win.title("Encrypt a Message")
    enc_win.geometry("400x300")
    enc_win.configure(bg="#2c3e50")

    tk.Label(enc_win, text="Enter Secret Key:", font=("Arial", 12), fg="white", bg="#2c3e50").pack()
    secret_key_entry = tk.Entry(enc_win, width=30, show="*", font=("Arial", 12))
    secret_key_entry.pack()

    tk.Label(enc_win, text="Enter Secret Message:", font=("Arial", 12), fg="white", bg="#2c3e50").pack()
    message_entry = tk.Entry(enc_win, width=30, font=("Arial", 12))
    message_entry.pack()

    def select_image():
        file_path = filedialog.askopenfilename()
        if file_path:
            encrypt_image(file_path, message_entry.get(), secret_key_entry.get())

    tk.Button(enc_win, text="Select Image & Encrypt", command=select_image, font=("Arial", 12), bg="#3498db", fg="white", width=20).pack(pady=10)

# Decryption Window
def open_decryption_window():
    dec_win = tk.Toplevel(root)
    dec_win.title("Decrypt a Message")
    dec_win.geometry("400x300")
    dec_win.configure(bg="#2c3e50")

    tk.Label(dec_win, text="Enter Secret Key:", font=("Arial", 12), fg="white", bg="#2c3e50").pack()
    secret_key_entry = tk.Entry(dec_win, width=30, show="*", font=("Arial", 12))
    secret_key_entry.pack()

    def select_image():
        file_path = filedialog.askopenfilename()
        if file_path:
            decrypt_image(file_path, secret_key_entry.get())

    tk.Button(dec_win, text="Select Image & Decrypt", command=select_image, font=("Arial", 12), bg="#e74c3c", fg="white", width=20).pack(pady=10)

def open_file_hiding_window():
    file_win = tk.Toplevel(root)
    file_win.title("Hide a File in Image")
    file_win.geometry("400x300")
    file_win.configure(bg="#2c3e50")
    selected_file = tk.StringVar()
    selected_image = tk.StringVar()

    def select_file():
        file_path = filedialog.askopenfilename(title="Select a File to Hide")
        if file_path:
            selected_file.set(file_path)

    def select_image():
        image_path = filedialog.askopenfilename(title="Select an Image")
        if image_path:
            selected_image.set(image_path)

    def hide_file():
        if selected_file.get() and selected_image.get():
            encrypt_image_with_file(selected_image.get(), selected_file.get())
        else:
            messagebox.showerror("Error", "Please select both a file and an image.")
    tk.Button(file_win, text="Select File", command=select_file, font=("Arial", 12), bg="#9b59b6", fg="white", width=20).pack(pady=5)
    tk.Label(file_win, textvariable=selected_file, fg="white", bg="#2c3e50").pack()

    tk.Button(file_win, text="Select Image", command=select_image, font=("Arial", 12), bg="#3498db", fg="white", width=20).pack(pady=5)
    tk.Label(file_win, textvariable=selected_image, fg="white", bg="#2c3e50").pack()

    tk.Button(file_win, text="Hide File in Image", command=hide_file, font=("Arial", 12), bg="#f1c40f", fg="black", width=20).pack(pady=10)



def open_file_extraction_window():
    extract_win = tk.Toplevel(root)
    extract_win.title("Extract File from Image")
    extract_win.geometry("400x300")
    extract_win.configure(bg="#2c3e50")

    def select_image():
        image_path = filedialog.askopenfilename(title="Select an Image")
        if image_path:
            decrypt_file_from_image(image_path)

    tk.Button(extract_win, text="Select Image & Extract", command=select_image, font=("Arial", 12), bg="#f1c40f", fg="black", width=20).pack(pady=10)

# Main GUI Window
root = tk.Tk()
root.title("Steganography Tool")
root.geometry("400x400")
root.configure(bg="#2c3e50")

# Title Label
title_label = tk.Label(root, text="Steganography Tool", font=("Arial", 16, "bold"), fg="white", bg="#2c3e50")
title_label.pack(pady=20)

# Buttons
encrypt_button = tk.Button(root, text="🔒 Encrypt Message", command=open_encryption_window, font=("Arial", 12), bg="#3498db", fg="white", width=20)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="🔓 Decrypt Message", command=open_decryption_window, font=("Arial", 12), bg="#e74c3c", fg="white", width=20)
decrypt_button.pack(pady=10)

tk.Button(root, text="📂 Hide File in Image", command=open_file_hiding_window, font=("Arial", 12), bg="#9b59b6", fg="white", width=20).pack(pady=10)
tk.Button(root, text="📤 Extract File from Image", command=open_file_extraction_window, font=("Arial", 12), bg="#f1c40f", fg="black", width=20).pack(pady=10)
tk.Button(root, text="Exit", command=root.quit, font=("Arial", 12), bg="#95a5a6", fg="black", width=20).pack(pady=10)

# Run the GUI
root.mainloop()
