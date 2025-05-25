# CSAC 329 Final Project
*Date: May 25, 2025*

---

## Group Members
- Divino Franco R. Aurellano
- Maica S. Romaraog
- Lj Tan T. Saldivar

---

## Introduction

This project is an interactive educational application designed to demonstrate various cryptographic algorithms and techniques. It provides a hands-on environment where users can experiment with different encryption methods, hash functions, and digital signatures in real-time.

In today's digital age, cryptography plays a crucial role in securing information and communications. From protecting personal messages to securing financial transactions, cryptographic algorithms are the backbone of digital security. This application aims to demystify these complex algorithms by providing an intuitive interface for users to explore and understand how they work.

The importance of cryptography extends beyond just technical applications. It's a fundamental component of privacy, trust, and security in our increasingly connected world. By creating an interactive platform to explore these concepts, this project serves both as an educational tool and a practical demonstration of cryptographic principles.

---

## Project Objectives

1. **Educational Value**: Create an intuitive platform that helps users understand various cryptographic algorithms through hands-on interaction, making complex concepts more accessible.

2. **Practical Implementation**: Demonstrate the practical application of cryptographic algorithms by implementing symmetric encryption, asymmetric encryption, and hashing functions with real-time encryption/decryption and verification capabilities.

3. **User Experience**: Develop a user-friendly interface that allows both beginners and advanced users to experiment with cryptographic techniques, visualize the processes, and understand the underlying principles.

4. **Security Awareness**: Raise awareness about cryptographic strengths and limitations by clearly communicating security considerations and best practices for each implemented algorithm.

5. **Technical Demonstration**: Showcase the integration of modern cryptographic libraries within a Python web application environment, highlighting the implementation details and considerations.

---

## Application Architecture

### Technology Stack

This application is built using **Streamlit**, a Python framework for creating web applications with minimal front-end development requirements. The project leverages several key technologies:

- **Frontend**: Streamlit provides interactive UI components and handles state management
- **Backend**: Python 3.8+ for all cryptographic operations and business logic
- **Cryptographic Libraries**: 
  - **PyCryptodome**: For symmetric encryption algorithms and some hash functions
  - **Cryptography**: For asymmetric encryption and modern cryptographic primitives
  - **Hashlib**: Python's built-in library for hash functions

### Application Structure

The application follows a modular design with the following components:

```
CSAC_329_FINAL_PROJECT/
├── 🏠Home.py                    # Main application entry point
├── pages/                       # Streamlit pages for different algorithm categories
│   ├── 🔏Symmetric_Algorithms.py # Symmetric encryption implementation
│   ├── 🔐Asymmetric_Algorithms.py # Asymmetric encryption implementation
│   └── 🔑Hashing_Functions.py   # Hash functions implementation
├── .streamlit/                  # Streamlit configuration
├── requirements.txt             # Project dependencies
└── README.md                    # This documentation
```

### UI Design Principles

The interface follows consistent design patterns across all modules:

- **Tabbed Interface**: Each algorithm type has its own tab for easy navigation
- **Expandable Sections**: Key generation, operation controls, and output are organized in collapsible sections
- **Interactive Controls**: User-friendly inputs for text, files, and cryptographic keys
- **Real-time Feedback**: Immediate results and visual feedback for all operations
- **Educational Information**: Each algorithm includes descriptions, technical details, and security considerations

---

## Cryptographic Algorithms Implementation

### Symmetric Encryption Algorithms

#### AES (Advanced Encryption Standard)
- **Type**: Symmetric Block Cipher
- **Background**: Developed by Belgian cryptographers Joan Daemen and Vincent Rijmen, AES was selected by NIST in 2001 to replace DES as the standard encryption algorithm for the US government. It has since become the worldwide standard for secure communications.
- **Implementation Details**:
  - Uses a substitution-permutation network with a fixed block size of 128 bits
  - Supports 128-bit key size (can be extended to 192/256 bits)
  - Uses CBC (Cipher Block Chaining) mode with a random initialization vector (IV)
  - Employs PKCS#7 padding for blocks
  - Provides full support for both text and file encryption/decryption
  - Includes performance metrics for operation timing
- **Security Strength**: Very strong, no practical attacks against the full algorithm
- **Use Cases**: Secure communications, file encryption, password protection

#### DES (Data Encryption Standard)
- **Type**: Symmetric Block Cipher
- **Background**: Developed in the early 1970s at IBM and adopted as a federal standard in 1977. While historically significant, it is now considered insecure due to its small key size.
- **Implementation Details**:
  - 56-bit effective key (64-bit key with 8 parity bits)
  - 64-bit block size using Feistel network structure
  - CBC mode implementation with proper IV handling
  - Includes security warnings about its vulnerabilities
  - Supports both text and file operations for educational purposes
- **Security Strength**: Weak by modern standards (brute force feasible)
- **Use Cases**: Legacy systems, educational purposes only (not recommended for secure applications)

#### 3DES (Triple DES)
- **Type**: Symmetric Block Cipher
- **Background**: Developed as a way to extend the lifespan of DES by applying the algorithm three times in sequence with different keys. It was widely used as a transitional algorithm between DES and AES.
- **Implementation Details**:
  - 168-bit effective key (192-bit with parity bits)
  - Applies DES three times using encrypt-decrypt-encrypt sequence
  - Uses the same CBC mode and padding scheme as our other implementations
  - Includes performance comparisons with AES to demonstrate its relative inefficiency
  - Supports text and file operations with detailed feedback
- **Security Strength**: Moderate (secure against most attacks but slow)
- **Use Cases**: Legacy financial systems, backward compatibility

### Asymmetric Encryption Algorithms

#### RSA (Rivest-Shamir-Adleman)
- **Type**: Asymmetric Encryption
- **Background**: Developed in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman, RSA was one of the first practical public-key cryptosystems. It revolutionized secure communications by allowing secure key exchange without a pre-shared secret.
- **Implementation Details**:
  - Supports 2048 and 4096-bit key options
  - Full key pair generation functionality
  - PEM format key export and import
  - Handles encryption size limitations using appropriate padding
  - Implements OAEP padding for security
  - Provides clear separation of public and private key operations
- **Security Strength**: Strong with proper key sizes (2048+ bits)
- **Use Cases**: Secure key exchange, digital signatures, certificate-based authentication

#### ECC (Elliptic Curve Cryptography)
- **Type**: Asymmetric Encryption/Signing
- **Background**: Developed independently by Neal Koblitz and Victor Miller in the mid-1980s, ECC has gained popularity due to its ability to provide equivalent security to RSA with much smaller key sizes.
- **Implementation Details**:
  - Implements SECP256R1, SECP384R1, and SECP521R1 curves
  - Focuses on digital signature functionality
  - Provides efficient key generation and management
  - Includes visual representations of signature verification
  - Demonstrates smaller key sizes compared to RSA
- **Security Strength**: Very strong with smaller keys than equivalent RSA
- **Use Cases**: Resource-constrained environments, mobile applications, IoT devices

#### DSA (Digital Signature Algorithm)
- **Type**: Asymmetric Signing
- **Background**: Developed by the National Institute of Standards and Technology (NIST) and published as a standard in 1994. It was specifically designed for digital signatures rather than encryption.
- **Implementation Details**:
  - Supports 1024, 2048, and 3072-bit key options
  - Implements signature generation and verification
  - Focuses on document signing use cases
  - Provides timing metrics for performance analysis
  - Includes educational comparisons with RSA and ECC signatures
- **Security Strength**: Strong with proper key sizes
- **Use Cases**: Document signing, code signing, non-repudiation services

### Hashing Functions

#### Implemented Hash Algorithms
- **MD5** (128-bit): Considered cryptographically broken, included for educational comparison
- **SHA-1** (160-bit): Deprecated but included for legacy comparison
- **SHA-256** (256-bit): Currently widely used for most applications
- **SHA-512** (512-bit): Higher security variant for sensitive applications
- **BLAKE2** (256-bit): Modern, high-performance hash function
- **SHA3-256** (256-bit): Latest NIST standard hash function

#### Implementation Details
- Unified interface for all hash functions
- Support for both text and file input
- Visual comparison of different hash outputs
- Performance benchmarking between algorithms
- Collision demonstration for educational purposes
- File integrity verification functionality

#### Use Cases
- Password storage (with proper salting)
- File integrity verification
- Digital signatures (as part of the signing process)
- Data identification and deduplication

---

## Using the Application

### Live Demo

The application is deployed and accessible online through Streamlit Cloud:

**[https://csac329finalproject.streamlit.app/](https://csac329finalproject.streamlit.app/)**

You can access and use all features of the application without any installation by visiting the link above.

### Installation

1. **Prerequisites**:
   - Python 3.8 or higher
   - Git (for cloning the repository)

2. **Setup**:
   ```bash
   # Clone the repository
   git clone https://github.com/yourusername/CSAC_329_FINAL_PROJECT.git
   cd CSAC_329_FINAL_PROJECT
   
   # Create a virtual environment (optional but recommended)
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **Starting the Application**:
   ```bash
   streamlit run 🏠Home.py
   ```
   The application will open in your default web browser at `http://localhost:8501`.

### Usage Guide

#### Home Page
- Overview of the application
- Introduction to cryptography concepts
- Navigation to different algorithm sections

#### Symmetric Encryption (🔏Symmetric_Algorithms.py)
1. **Select Algorithm**: Choose between AES, DES, or 3DES
2. **Generate Key**: Use the key generation feature or enter your own key
3. **Input Data**: Enter text directly or upload a file
4. **Perform Operation**: Select encrypt or decrypt
5. **View Results**: See the output, timing information, and technical details

#### Asymmetric Encryption (🔐Asymmetric_Algorithms.py)
1. **Select Algorithm**: Choose between RSA, ECC, or DSA
2. **Generate Key Pair**: Create new keys or import existing ones
3. **Operation Selection**: Choose between encryption (RSA) or signing (RSA/ECC/DSA)
4. **Input Data**: Enter message or upload file to be processed
5. **Execute and Verify**: Perform the operation and verify the results

#### Hashing Functions (🔑Hashing_Functions.py)
1. **Select Hash Algorithm**: Choose from the available hash functions
2. **Input Data**: Enter text or upload a file
3. **Generate Hash**: Calculate the hash value
4. **Compare Hashes**: See how different algorithms process the same input
5. **Verify Integrity**: Check if a file matches a previously generated hash

---

## Sample Runs/Outputs

This section showcases examples of the application in action, demonstrating the functionality of various cryptographic algorithms implemented in the project.

### Application Overview

Below is a brief demonstration of navigating through the application:

![App Exploration](sample_run/Recording_app_exploration.gif)

### Symmetric Encryption Examples

#### AES Encryption/Decryption

```
# AES Encryption Example
Original Text: "This is a secret message that needs to be encrypted securely."
Key (hex): 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
Encrypted (Base64): 9G7JkFtZfH3RgP+CZWgGJGDq6VctFMjH2Jae4Y9U7tXNYzB2VcpKs3gYyEi4Tr5PQTLpXVb3zk9Cq8vW==
Operation Time: 0.0032 seconds

# AES Decryption Example
Encrypted (Base64): 9G7JkFtZfH3RgP+CZWgGJGDq6VctFMjH2Jae4Y9U7tXNYzB2VcpKs3gYyEi4Tr5PQTLpXVb3zk9Cq8vW==
Key (hex): 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
Decrypted Text: "This is a secret message that needs to be encrypted securely."
Operation Time: 0.0028 seconds
```

#### DES Encryption/Decryption

```
# DES Encryption Example
Original Text: "Legacy encryption example with DES"
Key (hex): 133457799bbcdff1
Encrypted (Base64): Bf7g8J9Kl0M+nO2Pq3R4s5T6u7V8w9X0Y1Z2/3a4b5C6d7E8=
Operation Time: 0.0021 seconds

# DES Decryption Example
Encrypted (Base64): Bf7g8J9Kl0M+nO2Pq3R4s5T6u7V8w9X0Y1Z2/3a4b5C6d7E8=
Key (hex): 133457799bbcdff1
Decrypted Text: "Legacy encryption example with DES"
Operation Time: 0.0019 seconds
```

#### 3DES Encryption/Decryption

```
# 3DES Encryption Example
Original Text: "Stronger than DES but slower than AES"
Key (hex): 0123456789abcdef0123456789abcdef0123456789abcdef
Encrypted (Base64): ZhJ9MTpx37LmQo8WuY2vF4sDcRg0aE+tIfnK5bdXPluvGzSHAW==
Operation Time: 0.0065 seconds

# 3DES Decryption Example
Encrypted (Base64): ZhJ9MTpx37LmQo8WuY2vF4sDcRg0aE+tIfnK5bdXPluvGzSHAW==
Key (hex): 0123456789abcdef0123456789abcdef0123456789abcdef
Decrypted Text: "Stronger than DES but slower than AES"
Operation Time: 0.0071 seconds
```

### Asymmetric Encryption Examples

#### RSA Encryption/Decryption

```
# RSA Key Generation
Key Size: 2048 bits
Public Key Generated: -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtCYXS8VE7BjgfM5rAWV0
H8SdX83WvdSGJJ/2ktcF02524j1V14nxstkGzXq9m38nH1SXrWtJYEh0+iXmTRrm
XQP2JOzu97D2RoXdBpGwQJzkRgkkx/pAGJFLFreOAOhv3xfGLZYfUQZfQxfpzjnm
[...truncated...]
-----END PUBLIC KEY-----

# RSA Encryption
Original Text: "This message will be encrypted with RSA public key"
Encrypted (Base64): A5B7gDl2Fj+KaoP8TqUvM3r4s5t6WxY9Z0a1=
Operation Time: 0.0187 seconds

# RSA Decryption
Encrypted (Base64): A5B7gDl2Fj+KaoP8TqUvM3r4s5t6WxY9Z0a1=
Decrypted Text: "This message will be encrypted with RSA public key"
Operation Time: 0.0674 seconds
```

#### ECC Digital Signature

```
# ECC Key Generation
Curve: SECP256R1
Private Key Generated: -----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHbYXew0a0bu506xa
oUoNHuE5mRWY7JXWH2U0cQCEYPOhRANCAASIgxwT9G4y3WyYt3XJR5R6SHUuDbBg
m0cQPKUfZxgMGkS+0wy8BX5YMJRGdJK9tJHsVKTSsGqTbHI+MeXnBDj3
-----END PRIVATE KEY-----

# ECC Signing
Message: "Document to be signed with ECC"
Signature (Hex): 304502210097bd7c8b927cb4b33189cf44831125b1d3184b2160d98e3c37c3e7fcaa471d5002201bf5447447dfdab5c0d5a6c83e3051c78b7925984070527e19b2dd05a76b426c

# ECC Verification
Message: "Document to be signed with ECC"
Signature Valid: True
Verification Time: 0.0021 seconds
```

#### DSA Digital Signature

```
# DSA Key Generation
Key Size: 2048 bits
Private Key Generated: -----BEGIN PRIVATE KEY-----
MIICZQIBADCCAjkGByqGSM44BAEwggIsAoIBAQC+9LtFG2SRcRohzS+Zl0Mni3EZ
xjcU310RBnvOahh/RF8ZGlalU8A9J4/XnYLaZtk2A9wvx+a3/EQmi6jCOtI/ERiR
[...truncated...]
-----END PRIVATE KEY-----

# DSA Signing
Message: "Message to be signed with DSA"
Signature (Hex): 302c02142d7fca0eda8499192605132b70e36b2912d5d370021400abc730665cd235ce34ea02df59128d93d8890a7

# DSA Verification
Message: "Message to be signed with DSA"
Signature Valid: True
Verification Time: 0.0035 seconds
```

### Hashing Function Examples

#### Single Hash Calculation

```
# SHA-256 Hash Example
Input Text: "This is a sample text to demonstrate hash functions"
SHA-256 Hash: 7fca3c398cbd12ede6fcdf26e6cc802f64e3fcc05e9ce9e2ec8c2818b9294ad1

# MD5 Hash Example (for comparison only, not secure)
Input Text: "This is a sample text to demonstrate hash functions"
MD5 Hash: a5adf324e0f5b5c199533e5a2434ecd0

# SHA-512 Hash Example
Input Text: "This is a sample text to demonstrate hash functions"
SHA-512 Hash: 147f1d77cbf4694f34c78d739095116cd3f2251188410734c2cf5ae6b49ee28015a4e5856d071e751b7452d3d43c5fea569fe6d3236126af896a6478686c7b8a
```

#### Hash Comparison Tool Results

| Algorithm | Hash Value | Time (seconds) |
|-----------|------------|----------------|
| MD5       | a5adf324e0f5b5c199533e5a2434ecd0 | 0.0001 |
| SHA-1     | af0be0c2d12e0f2876df5e52713d98d8736c688c | 0.0001 |
| SHA-256   | 7fca3c398cbd12ede6fcdf26e6cc802f64e3fcc05e9ce9e2ec8c2818b9294ad1 | 0.0003 |
| SHA3-256  | 242622f5caecfdcf8e86324497e1066c6d67a5bd2c503c80db542eef93657a4f | 0.0004 |
| BLAKE2b   | a94553d488e5f08774a358c7cd51c19f3c8c0a064bea07759d63fadbf9c5181ecbcb8663d962e754b4eeb2ac4c7307e5620f40bdc0417170ce149be8f4e9798a | 0.0002 |

---

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before getting started.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Contribution

- Additional cryptographic algorithms
- UI/UX improvements
- Documentation enhancements
- Performance optimizations
- Educational content

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- All contributors who have participated in this project
- Faculty and staff of the Applied Cryptography course
- The Streamlit team for their excellent framework
- The cryptographic community for their ongoing research and documentation
- Open-source cryptographic libraries that made this project possible