# Applied Cryptography Project

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

This is an educational project for the Applied Cryptography course that demonstrates various cryptographic algorithms, their implementations, and applications. The project is designed to help students understand cryptographic principles through interactive demonstrations.

## Features

- **Symmetric Encryption Algorithms**: Implementation and demonstration of AES, DES, and other symmetric encryption techniques
- **Asymmetric Encryption**: Implementation and demonstration of RSA, ECC, and other public-key cryptography techniques
- **Hashing Functions**
- **Interactive Web Interface**: Built with Streamlit for intuitive, visual learning experiences

## Getting Started

### Prerequisites

- Python 3.6+
- pip (Python package installer)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/YourUsername/CSAC_329_FINAL_PROJECT.git
   cd CSAC_329_FINAL_PROJECT
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   streamlit run Home.py
   ```

## Project Structure

- `Home.py`: Main entry point for the Streamlit application
- `pages/`: Directory containing specific pages for different cryptographic categories
  - `symmetric_algo/`: Demonstrations of symmetric encryption algorithms
  - `asymmetric_algo/`: Demonstrations of asymmetric encryption algorithms
  - `hashing_functions/`: Demonstrations of cryptographic hash functions

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before getting started.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- All contributors who have participated in this project
- Faculty and staff of the Applied Cryptography course
- Open-source cryptography libraries used in this project