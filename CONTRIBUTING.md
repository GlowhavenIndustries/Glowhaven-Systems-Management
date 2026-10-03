# Contributing to Glowhaven Atlas

Thank you for your interest in contributing to Glowhaven Atlas! Atlas is an open-source server lifecycle platform designed for infrastructure and operations teams.

## Code of Conduct

We are committed to providing a welcoming, inclusive, and safe environment for all contributors. Please treat everyone with respect, courtesy, and empathy.

## Repository Topic Tags and Discoverability

To help operators and sysadmins discover Atlas on GitHub, this project focuses on the following primary topic tags:

- `server-management`
- `infrastructure-automation`
- `fleet-management`
- `sysadmin-tools`
- `systemd`
- `fastapi`
- `agent-based`
- `patch-management`
- `audit-logging`
- `linux-administration`

When adding integration adapters, documentation, or new agent capabilities, keep these core topic areas in mind.

## How to Contribute

### 1. Reporting Bugs

Before creating a bug report, check the existing GitHub Issues to see if the issue has already been reported. If not, please open a new issue using the **Bug Report** template.

Include:
- OS version (Controller and target Host Agent)
- Python version
- Clear steps to reproduce
- Relevant non-sensitive logs

*Note: For security vulnerabilities, do not open a public issue. Follow the instructions in [SECURITY.md](SECURITY.md).*

### 2. Suggesting Enhancements

We welcome ideas for new adapters, UI improvements, and workflow enhancements! Please check existing issues or roadmap discussions first, then submit a **Feature Request** using the provided template.

### 3. Submitting Code Changes

1. **Fork and clone** the repository:
   ```bash
   git clone https://github.com/GlowhavenIndustries/Glowhaven-Systems-Management.git
   cd Glowhaven-Systems-Management
   ```

2. **Set up a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements-dev.txt
   ```

3. **Create a topic branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Code style & quality guidelines**:
   - Keep the codebase simple, explicit, and readable.
   - Do not use em dash characters (Unicode U+2014) in documentation, code comments, or commit messages.
   - Follow standard Python PEP 8 conventions.
   - Validate Python syntax:
     ```bash
     python -m py_compile atlas/*.py agent/*.py
     ```

5. **Testing**:
   - Write unit tests for new functionality in the `tests/` directory.
   - Run the full backend test suite to ensure no regressions:
     ```bash
     python3 -m pytest
     ```

6. **Submit a Pull Request**:
   - Ensure all CI tests pass.
   - Provide a concise title and detailed description of the changes.

## Security Disclosures

If you discover a security vulnerability in Glowhaven Atlas, please report it privately via GitHub Security Advisories (**Security -> Report a vulnerability**). See [SECURITY.md](SECURITY.md) for details.

Thank you for helping make Glowhaven Atlas better for everyone!
