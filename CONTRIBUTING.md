# Contributing to Applied Cryptography Project

First off, thank you for considering contributing to this project. It's people like you that make this project better for everyone.

## Getting Started

- Fork the repository on GitHub
- Clone your fork locally: `git clone https://github.com/YourUsername/CSAC_329_FINAL_PROJECT.git`
- Set up your local environment: Create a virtual environment and install dependencies
  ```bash
  python -m venv venv
  source venv/bin/activate  # On Windows: venv\Scripts\activate
  pip install -r requirements.txt
  ```
- Create a branch for your feature or fix: `git checkout -b feature/your-feature-name`

## Development Process

1. Make your changes
2. Test your changes locally
3. Commit your changes with a descriptive commit message
   ```bash
   git commit -m "Add feature: your feature description"
   ```
4. Push to your fork: `git push origin feature/your-feature-name`
5. Submit a pull request to the main repository

## Pull Request Guidelines

- Update the README.md with details of changes to the interface, if applicable
- Update the documentation with details of any new functionality
- The PR should work for Python 3.6 and above
- Make sure your code lints

## Code Style

- Follow PEP 8 style guidelines for Python code
- Use meaningful variable names
- Write descriptive comments
- Keep functions small and focused

## Cryptography Best Practices

When contributing cryptographic implementations:

- Always use well-established libraries instead of implementing algorithms from scratch
- Follow security best practices (e.g., avoid timing attacks, use secure random generators)
- Document security considerations and limitations


## Documentation

- Update documentation to reflect any changes or additions
- Use clear, concise language
- Include examples where appropriate

## Code of Conduct

Please note that this project adheres to our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Questions?

Don't hesitate to create an issue or contact the project maintainers if you have any questions or concerns.

Thank you for your contributions!
