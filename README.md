# AntiCryptoJS Burp Suite Extension

This Burp Suite extension provides encryption and decryption capabilities using AES and DES algorithms. It allows you to manipulate data directly in Burp Suite tools like Repeater and Intruder, with an additional AntiCryptoJS tab for manual encryption and decryption tasks.

## Features

- **AntiCryptoJS Tab**: Manually encrypt or decrypt text using a user-friendly interface.
- **Repeater and Intruder Integration**: Encrypt or decrypt highlighted text using AES or DES from the context menu.
- **Payload Processing**: Automate encryption/decryption of payloads in Intruder with dynamic processing.

## Installation

### Prerequisites

Ensure Burp Suite is set up and running with Python extension support [Jython](https://www.jython.org/download.html).

### Steps to Install

1. Open **Burp Suite** and navigate to the **Extender** tab.
2. Click on the **Add** button to install a new extension.
3. In the popup, set the **Extension Type** to **Python**.
4. Locate and select the `AntiCryptoJS.py` file.
5. Click **Next**, and the extension will be added to Burp Suite.

## Usage

### AntiCryptoJS Tab

A new **AntiCryptoJS** tab will appear in Burp Suite. This tab allows manual input for encryption and decryption of data.

1. Choose the algorithm (AES or DES).
2. Enter the encryption key.
3. Enter the initialization vector (IV).
4. Input the text you want to encrypt or decrypt.

### Repeater Integration

1. Highlight the text (plaintext or ciphertext) in Repeater.
2. Right-click to open the context menu.
3. Select Extensions => AntiCryptoJS => **Encrypt** or **Decrypt** based on your need.
4. The highlighted text will be replaced with the encrypted or decrypted result.

### Intruder Payload Processing

1. Add a target request to Intruder.
2. Set the payload positions.
3. Select **AntiCryptoJS** in the **Payload Processing** dropdown.
4. Configure the encryption algorithm, key, and IV.
5. As payloads are sent, they will be encrypted.

## Notes

- Ensure the key and IV lengths are appropriate for the selected algorithm:
  - **AES**: Key lengths of 16, 24, or 32 bytes; IV length of 16 bytes.
  - **DES**: Key length of 8 bytes; IV length of 8 bytes.
  
## License

This project is licensed under the [MIT License](LICENSE).

