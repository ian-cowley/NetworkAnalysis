# Project Specification: Live PCAP LLM Analyst (NetworkAnalysisApp v2.0)

## 1. Concept & Objective
**The Problem**: Reading decrypted HTTP/2, JSON payloads, or raw binary data from packet captures is tedious and often requires deep domain knowledge to understand what an application is actually doing (e.g., telemetry, tracking, background updates).
**The Solution**: Integrate a localized Large Language Model (LLM) directly into the `NetworkAnalysisApp`. When a user clicks on a decrypted TLS packet or a complex plaintext flow, they can click "Explain this Traffic." The local LLM will read the payload and provide a human-readable summary of the network activity.

**Key Rule**: 100% Offline and Private. Analyzing sensitive decrypted traffic using a cloud provider (like OpenAI) is a massive security risk. This project must use a quantized, locally-running model to ensure zero data exfiltration.

## 2. Technical Stack
* **Language & UI**: C#, WPF (`NetworkAnalysisApp`).
* **AI Runtime**: `LLamaSharp` (A C# binding for `llama.cpp` that allows running GGUF models directly in .NET without Python or external dependencies).
* **The Model**: `Phi-3-Mini` (Microsoft's highly capable 3.8B parameter model, quantized to 4-bit GGUF, ~2.3GB download) or a small `Llama-3-8B` instruct model.
* **Integration Point**: The existing `MainWindow.xaml` UI and the `PacketModel.DecryptedPayload`.

## 3. Core Features to Implement

### Feature A: The "AI Analyst" UI Panel
Extend the "Packet Details" pane in the lower right of the `NetworkAnalysisApp`.
1. Add a new Tab next to "Hex View", "Text View", and "Decrypted Text" named **"AI Analyst"**.
2. This tab contains a simple read-only text block for the LLM's response, and a prominent "Analyze Payload" button.
3. Introduce a "Model Loading" indicator to show when the AI engine is booting up into RAM/VRAM.

### Feature B: The LLamaSharp Inference Engine
Build a dedicated service to handle the heavy lifting of running the LLM.
1. **Model Management**: Have a settings page where the user can specify the path to their downloaded `.gguf` model file.
2. **The Prompt Template**: When the user clicks "Analyze", the app constructs a prompt like:
   ```text
   You are an expert network security analyst. Explain the purpose of this network request 
   in plain English. Be concise.
   
   [PAYLOAD]
   POST /telemetry/v1 HTTP/2
   Host: browser.events.com
   Content-Type: application/json
   {"os": "Windows 11", "resolution": "1920x1080", "battery": 87}
   [/PAYLOAD]
   ```
3. **Streamed Responses**: Implement `IAsyncEnumerable` or a background task to stream the LLM's generated text back to the WPF UI token-by-token, exactly like ChatGPT. This keeps the UI responsive and engaging.

### Feature C: Contextual Prompts (Advanced)
If the payload is too large for the LLM's context window (e.g., a massive image download), build logic to intelligently slice or summarize the payload before feeding it to the AI. E.g., strip out the binary body and only send the HTTP headers.

## 4. Implementation Roadmap

**Phase 1: Environment Setup**
* Add the `LLamaSharp` and `LLamaSharp.Backend.Cpu` (or `Cuda` for GPU support) NuGet packages to `NetworkAnalysisApp`.
* Create a simple console app test project just to verify you can load a `gguf` model and generate "Hello World" to prove the integration works on your hardware.

**Phase 2: The UI Framework**
* Update `MainWindow.xaml` to include the "AI Analyst" tab.
* Add bindings in `MainViewModel` for the `IsAnalyzing` boolean (to show a spinner) and `AiAnalysisText` string.

**Phase 3: The `NetworkAiService`**
* Create a Singleton service that initializes the `LLamaContext` when the app starts.
* Write the `AnalyzePayloadAsync(byte[] decryptedData)` method.
* Design the system prompt to guide the AI to act as a security analyst, preventing it from hallucinating or refusing to answer.

**Phase 4: Optimization and Polish**
* Add options to use GPU acceleration if available.
* Handle edge cases (e.g., non-decrypted packets, packets with no payload).
* Add a disclaimer that AI analysis is a supplementary tool and entirely localized.

## 5. Why This Project Stands Out

Networking tools like Wireshark are incredibly powerful, but parsing the data is a manual, tedious process. By combining your custom, zero-dependency `TlsDecryptionEngine` with a fully localized, private instance of a modern LLM via `LLamaSharp`, you are building something that merges deep systems programming with cutting-edge AI. 

It proves you can integrate native C/C++ AI libraries (`llama.cpp` via bindings) into polished C# desktop applications, a highly sought-after skill in enterprise AI adoption where data privacy is paramount.
