# NetworkAnalysisApp

A powerful, native Windows application written in C# and WPF for capturing, analyzing, and decrypting network traffic. It features a custom-built, dependency-free TLS 1.2/1.3 decryption engine capable of correlating browser keylogs to decrypt and visualize application-layer data (like HTTP/2) on the fly.

## Features

- **Live Packet Capture**: Intercept and visualize live traffic using WinPcap/Npcap.
- **TLS 1.3 Decryption**: Native `TlsDecryptionEngine` that reassembles TCP streams, parses TLS records, and uses HKDF and AES-GCM to decrypt payloads on the fly using standard `SSLKEYLOGFILE` formats.
- **Offline AI Analyst**: Built-in HTTP payload summarization powered by `Microsoft.ML.OnnxRuntimeGenAI`. It runs quantized LLMs (like Phi-3 or Llama-3) locally with full hardware acceleration via DirectML.
- **Traffic Slicing & Filtering**: Supports standard BPF syntax filtering (e.g. `port 443`) and bidirectional tracking.
- **Decrypted Payload Visualization**: Built-in hex viewer and text viewer for inspecting decrypted HTTP requests and headers.
- **Smart History**: Persents previously used IPs and BPF filters for quick access.

## Architecture

The project is split into two primary components:
1. `NetworkAnalysisApp` - A robust, visually-appealing WPF UI that leverages `SharpPcap` for network listening and handles configuration and user experience.
2. `TlsDecryptionEngine` - A standalone class library that implements a custom TCP stream reassembler, handshakes tracker, and TLS decryption mechanics using standard `.NET` cryptographic primitives.

## Prerequisites

- .NET 8.0 SDK (or later)
- WinPcap, Npcap, or Wireshark installed (for driver support)
- Google Chrome or Microsoft Edge (for generating active `SSLKEYLOGFILE` keys via the UI)

## Getting Started

1. Clone the repository: `git clone https://github.com/yourusername/NetworkAnalysis.git`
2. Open `NetworkAnalysis.slnx` or `NetworkAnalysisApp.sln`.
3. Set `NetworkAnalysisApp` as the startup project and run.
4. Go to **Settings** and ensure the Browser Path and Key Log Path are correctly defined.
5. Click **Launch Browser** from the UI. This launches the browser with QUIC disabled, forcing it to use trackable TCP-based TLS and aggressively log traffic keys to the path specified in your settings.
6. Observe as live `ApplicationData` is decrypted right before your eyes!

## Credits
- Developed by **Ian Cowley** and **Antigravity** (Google DeepMind).

## License
MIT License - See the [LICENSE](LICENSE) file for more details.
