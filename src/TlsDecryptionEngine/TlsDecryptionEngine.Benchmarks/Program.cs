using System;
using BenchmarkDotNet.Running;

namespace TlsDecryptionEngine.Benchmarks;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("=== Starting Engine Benchmarks ===");
        var summary = BenchmarkRunner.Run<PerformanceBenchmarks>();
        Console.WriteLine("Benchmarks complete.");
    }
}
