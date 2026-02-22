using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.ML.OnnxRuntimeGenAI;
using NetworkAnalysisApp.Models;

namespace NetworkAnalysisApp.Services
{
    public class AiAnalystService : IDisposable
    {
        private Model? _model;
        private Tokenizer? _tokenizer;
        private bool _isInitialized = false;
        private AppConfig _config;

        public AiAnalystService(AppConfig config)
        {
            _config = config;
        }

        public async Task InitializeAsync()
        {
            if (_isInitialized) return;

            if (string.IsNullOrWhiteSpace(_config.AiModelPath) || !Directory.Exists(_config.AiModelPath))
            {
                throw new DirectoryNotFoundException($"ONNX AI Model folder not found at: {_config.AiModelPath}\nPlease download the directml int4 ONNX model folder (it must contain the .onnx file and genai_config.json).");
            }

            await Task.Run(() =>
            {
                // This will automatically pick up DirectML acceleration if configured in the model's genai_config.json
                _model = new Model(_config.AiModelPath);
                _tokenizer = new Tokenizer(_model);
                _isInitialized = true;
            });
        }

        public async IAsyncEnumerable<string> AnalyzePayloadAsync(string payload, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            if (!_isInitialized || _model == null || _tokenizer == null)
            {
                await InitializeAsync();
            }

            // Phi-3 specific chat template format
            var prompt = $"<|system|>\n{_config.AiSystemPrompt}<|end|>\n<|user|>\n[PAYLOAD START]\n{payload}\n[PAYLOAD END]\nAnalysis:<|end|>\n<|assistant|>\n";

            // Tokenize
            using var tokens = _tokenizer!.Encode(prompt);

            using var generatorParams = new GeneratorParams(_model!);
            generatorParams.SetSearchOption("max_length", 2048);
            generatorParams.SetSearchOption("temperature", 0.3);

            using var tokenizerStream = _tokenizer.CreateStream();
            using var generator = new Generator(_model!, generatorParams);
            
            generator.AppendTokens(tokens[0]);

            string outputBuffer = "";
            while (!generator.IsDone())
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                // Compute next token off the UI thread
                await Task.Run(() =>
                {
                    generator.GenerateNextToken();
                }, cancellationToken);
                
                var currentToken = generator.GetSequence(0)[^1];
                var tokenStr = tokenizerStream.Decode(currentToken);
                
                // Force break if the model generates a chat template end token natively
                if (tokenStr.Contains("<|end|>") || tokenStr.Contains("<|user|>") || tokenStr.Contains("<|assistant|>"))
                {
                    break;
                }

                outputBuffer += tokenStr;

                // Stop if the model starts hallucinating a repetitive loop of new answers
                if (outputBuffer.Contains("[ANSWER END]\r\n\r\n[ANSWER START]") || 
                    outputBuffer.Contains("[ANSWER END]\n\n[ANSWER START]"))
                {
                    break;
                }

                yield return tokenStr;
            }
        }

        public void Dispose()
        {
            _tokenizer?.Dispose();
            _model?.Dispose();
        }
    }
}
