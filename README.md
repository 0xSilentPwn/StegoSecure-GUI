# 🔐 Steganography GUI Tool

This project implements Steganography to securely hide text messages and files inside images using LSB (Least Significant Bit) encoding. It is a Graphical User Interface (GUI) Steganography Tool that allows users to hide secret messages inside images and retrieve them securely using a secret key. The tool provides an easy-to-use interface for encryption and decryption. It features a modern UI and separate encryption & decryption windows.

## 📌 Features

✔ Encryption: Hide a secret message inside an image using a GUI.

✔ Decryption: Extract the hidden message from the image via GUI.

✔ Passcode Protection: Only users with the correct passcode can decrypt the message.

✔ Automatic Message Length Handling: No need to manually enter message length.

✔ Restores Original Image After Decryption.

✔ User-Friendly GUI for Ease of Use.

✔ Multiple Image Format Support – Works with PNG, JPG, BMP images.

✔ File Hiding – Hide any file (ZIP, EXE, TXT, etc.) inside an image.

## 📂 Project Structure:

📁 Steganography-Tool/

- │── stego_gui.py      # Main GUI script (Encryption & Decryption)
- │── requirements.txt  # Required dependencies
- │── README.md         # Project documentation

## 📌 Installation

1️⃣ Clone the Repository

git clone (https://github.com/0xSilentPwn/StegoSecure.git)

cd StegoSecure-GUI

2️⃣ Install Required Dependencies

pip install -r requirements.txt

## 📌 Future Scope

🔹 AES Encryption – Encrypt hidden data for extra security.

🔹 Steganalysis Detection Tool – Detect images containing hidden data.

🔹 Cross-Platform Support – Develop a mobile app for steganography.

## License
This project is licensed under the [MIT License](LICENSE).

## Contributors
- [0xSilentPwn](https://github.com/0xSilentPwn)
