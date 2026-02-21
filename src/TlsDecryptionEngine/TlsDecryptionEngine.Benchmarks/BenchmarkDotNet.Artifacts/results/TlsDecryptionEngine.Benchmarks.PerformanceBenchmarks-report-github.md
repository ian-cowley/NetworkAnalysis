```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.7840/25H2/2025Update/HudsonValley2)
AMD Ryzen AI 9 HX 370 w/ Radeon 890M 2.00GHz, 1 CPU, 24 logical and 12 physical cores
.NET SDK 10.0.200-preview.0.26103.119
  [Host]   : .NET 8.0.24 (8.0.24, 8.0.2426.7010), X64 RyuJIT x86-64-v4
  ShortRun : .NET 8.0.24 (8.0.24, 8.0.2426.7010), X64 RyuJIT x86-64-v4

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method                                           | Mean      | Error      | StdDev    | Gen0     | Gen1     | Gen2     | Allocated  |
|------------------------------------------------- |----------:|-----------:|----------:|---------:|---------:|---------:|-----------:|
| &#39;TCP Stream Reassembly (Optimized MemoryStream)&#39; | 438.83 μs | 347.707 μs | 19.059 μs | 961.4258 | 953.1250 | 952.6367 | 4498.58 KB |
| &#39;TLS 1.3 HKDF Extraction (AES-NI)&#39;               |  21.36 μs |   2.218 μs |  0.122 μs |   0.6409 |        - |        - |    5.47 KB |
