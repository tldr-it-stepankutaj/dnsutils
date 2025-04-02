# Contributing to DNS Reconnaissance Tool

Thank you for your interest in contributing to the DNS Reconnaissance Tool! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Setting Up Development Environment](#setting-up-development-environment)
  - [Understanding the Project Structure](#understanding-the-project-structure)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Development Guidelines](#development-guidelines)
  - [Coding Standards](#coding-standards)
  - [Testing](#testing)
  - [Documentation](#documentation)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Release Process](#release-process)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [stepan.kutaj@tldr-it.com](mailto:stepan.kutaj@tldr-it.com).

## Getting Started

### Setting Up Development Environment

1. **Prerequisites**:
   - Go 1.21 or later
   - Git

2. **Fork and Clone**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/dnsutils.git
   cd dnsutils
   ```

3. **Set up Remotes**:
   ```bash
   git remote add upstream https://github.com/tldr-it-stepankutaj/dnsutils.git
   ```

4. **Build the Project**:
   ```bash
   make build
   ```

### Understanding the Project Structure

The project is organized as follows:
```
.
├── cmd
│   └── main.go            # Application entry point
├── internal
│   ├── asn
│   │   └── lookup.go      # ASN lookup functionality
│   ├── dns
│   │   └── resolver.go    # DNS record retrieval
│   ├── models
│   │   └── models.go      # Data structures
│   ├── output
│   │   ├── console.go     # Console output formatting
│   │   └── json.go        # JSON output
│   ├── scanner
│   │   └── portscanner.go # Port scanning and service detection
│   ├── ssl
│   │   └── certificate.go # SSL certificate handling
│   └── subdomain
│       ├── bruteforce.go  # Brute force subdomain discovery
│       └── certs.go       # Subdomain discovery via certs
└── pkg
    └── utils
        └── utils.go       # Utility functions
```

## How to Contribute

### Reporting Bugs

Bugs are tracked as GitHub issues. Create an issue and provide the following information:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the bug
- Provide specific examples, such as code snippets or terminal commands
- Describe the observed behavior vs the expected behavior
- Include relevant logs, screenshots, or terminal output

### Suggesting Enhancements

Enhancement suggestions are also tracked as GitHub issues:

- Use a clear and descriptive title
- Provide a detailed description of the suggested enhancement
- Explain why this enhancement would be useful to most users
- Provide examples of how it would be used
- Include any relevant mockups or diagrams

### Pull Requests

1. **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**:
   - Implement your feature or fix
   - Add or update tests as needed
   - Update documentation to reflect your changes

3. **Run Tests**:
   ```bash
   go test ./...
   ```

4. **Commit Your Changes**:
   ```bash
   git commit -m "Add detailed, descriptive commit message"
   ```

5. **Push to Your Fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit a Pull Request**:
   - Fill in the provided PR template
   - Reference any related issues
   - Describe your changes in detail

7. **Code Review**:
   - Wait for maintainers to review your PR
   - Make any requested changes

## Development Guidelines

### Coding Standards

- Follow Go's official [Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Run `go fmt` before submitting your code
- Use `golint` and `go vet` to check your code
- Keep functions small and focused on a single task
- Write descriptive variable and function names

### Testing

- Write tests for all new code
- Ensure all tests pass before submitting a PR
- Aim for high code coverage
- Include both unit tests and integration tests when appropriate

### Documentation

- Update documentation to reflect your changes
- Document exported functions, types, and methods
- Include examples where appropriate
- Keep the README up to date with any new features

## Commit Message Guidelines

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests after the first line
- Consider using the following format:
  ```
  [FEATURE/FIX/DOCS/TEST/REFACTOR]: Brief description

  Longer description if necessary. Explain the problem that this commit is solving.
  Reference any issues or PRs: #123, #456
  ```

## Release Process

The maintainers follow this process for releases:

1. Update version numbers in relevant files
2. Create a changelog entry
3. Tag the release in Git
4. Build and publish binaries to the GitHub Releases page

## Community

- Join discussions in the GitHub Issues section
- Follow the project author on [GitHub](https://github.com/tldr-it-stepankutaj) or [LinkedIn](https://www.linkedin.com/in/stepankutaj)
- Contact the author directly at [stepan.kutaj@tldr-it.com](mailto:stepan.kutaj@tldr-it.com) or visit [www.tldr-it.com](https://www.tldr-it.com)

---

Thank you for contributing to the DNS Reconnaissance Tool!
