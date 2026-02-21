# Contributing to NetworkAnalysisApp

Thank you for your interest in contributing to the **NetworkAnalysisApp** project! We appreciate help from the community.

## Getting Started

1. **Fork the Repository**: Start by forking the project to your own GitHub account.
2. **Review Issues**: Check out the issues tab for "Good First Issue" tags or features that need help.
3. **Local Setup**: 
   - Ensure you have the .NET 8.0 SDK or later.
   - Install Wireshark, Npcap, or WinPcap to enable network listening on your machine.
   - Open `NetworkAnalysis.slnx` and ensure both projects build successfully.

## Coding Standards

- The engine and app use modern C# 12+ language features.
- Please ensure that any changes cleanly encapsulate logic inside `TlsDecryptionEngine` where appropriate—UI updates belong strictly in `NetworkAnalysisApp`.
- Document new functionality thoroughly and provide inline comments for complex crypto logic.

## Pull Requests

- Create a new branch for your feature or bug fix: `git checkout -b feature/your-feature-name`.
- Make focused, atomic commits.
- Ensure all existing and any new unit tests inside `TlsDecryptionEngine.Tests` pass (`dotnet test`).
- Open a Pull Request referencing the Issue it resolves.

We look forward to reviewing your PR!
