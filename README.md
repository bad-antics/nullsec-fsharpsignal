# NullSec FSharpSignal

**Threat Signal Correlator** written in F#

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bad-antics/nullsec-fsharpsignal/releases)
[![Language](https://img.shields.io/badge/language-F%23-378BBA.svg)](https://fsharp.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Part of the **NullSec** offensive security toolkit  
> Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)  
> Portal: [bad-antics.github.io](https://bad-antics.github.io)

## Overview

FSharpSignal is a threat intelligence correlation engine that aggregates indicators of compromise (IOCs) and identifies attack patterns through functional programming paradigms. Built with F#'s discriminated unions, pattern matching, and immutable data structures.

## F# Features Showcased

- **Discriminated Unions**: Type-safe threat categories
- **Active Patterns**: Custom pattern matching
- **Computation Expressions**: Signal builder monad
- **Higher-Order Functions**: Composable pipelines
- **Record Types**: Immutable data structures
- **Pattern Matching**: Exhaustive case handling
- **List Comprehensions**: Functional collections
- **Type Inference**: Clean, concise code

## Correlation Rules

| Rule | Description | Required Types | MITRE |
|------|-------------|----------------|-------|
| APT Campaign | Multi-vector campaign detection | IP, Domain, Hash | TA0001 |
| C2 Infrastructure | Command & control patterns | IP, Domain | T1071 |
| Lateral Movement | Network traversal indicators | IP, Process | TA0008 |
| Data Staging | Exfiltration preparation | Hash, Process, Registry | T1074 |
| Phishing Infrastructure | Phishing campaign IOCs | Domain, Email, URL | T1566 |

## Installation

```bash
# Clone
git clone https://github.com/bad-antics/nullsec-fsharpsignal.git
cd nullsec-fsharpsignal

# Build with .NET SDK
dotnet build

# Or compile directly
fsharpc FSharpSignal.fs -o fsharpsignal.exe
```

## Usage

```bash
# Run demo mode
dotnet run

# Process IOC file
dotnet run -- -f indicators.json

# Enable verbose correlation
dotnet run -- -v -f indicators.json
```

### Options

```
USAGE:
    fsharpsignal [OPTIONS]

OPTIONS:
    -h, --help       Show help
    -f, --file       IOC file to process
    -v, --verbose    Verbose output
    -r, --rules      Custom correlation rules
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════╗
║        NullSec FSharpSignal - Threat Signal Correlator           ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Loading threat intelligence indicators...

  Loaded 13 indicators

Running correlation engine...

  ╔═══════════════════════════════════════════════════════════════╗
  ║  CORRELATED SIGNAL: APT Campaign Detection                    ║
  ╚═══════════════════════════════════════════════════════════════╝
    
    Severity:     CRITICAL
    Score:        42.5/100
    MITRE ID:     TA0001
    Correlation:  2024-01-15 14:30:22 UTC
    
    Indicators:
      [HIGH] IP: 185.220.101.45
      [HIGH] Domain: update-service.duckdns.org
      [CRITICAL] Hash: 44d88612fea8a8f36de82e1278abb02f

  ╔═══════════════════════════════════════════════════════════════╗
  ║  CORRELATED SIGNAL: C2 Infrastructure                         ║
  ╚═══════════════════════════════════════════════════════════════╝
    
    Severity:     HIGH
    Score:        28.0/100
    MITRE ID:     T1071
    Correlation:  2024-01-15 14:30:22 UTC
    
    Indicators:
      [HIGH] IP: 185.220.101.45
      [HIGH] Domain: c2-beacon.no-ip.com

═══════════════════════════════════════════════════════════════════

  Summary:
    Total Signals:    4
    Critical:         1
    High:             2
    Medium:           1
    Combined Score:   112.5
```

## Code Highlights

### Discriminated Unions for Type Safety
```fsharp
type Severity =
    | Critical
    | High
    | Medium
    | Low
    | Informational

type IndicatorType =
    | IPAddress
    | Domain
    | FileHash
    | URL
    | Email
    | Registry
    | ProcessName
    | Mutex
```

### Active Patterns for Custom Matching
```fsharp
let (|C2Domain|PhishingDomain|LegitDomain|) (domain: string) =
    let c2Patterns = [".onion"; ".bit"; "duckdns.org"; "no-ip.com"]
    let phishingKeywords = ["login"; "secure"; "verify"]
    let lowerDomain = domain.ToLowerInvariant()
    if c2Patterns |> List.exists (fun p -> lowerDomain.EndsWith(p)) then C2Domain
    elif phishingKeywords |> List.exists (fun k -> lowerDomain.Contains(k)) then PhishingDomain
    else LegitDomain

// Usage
let enrichDomain indicator =
    match indicator.Value with
    | C2Domain -> { indicator with Category = C2Infrastructure }
    | PhishingDomain -> { indicator with Category = Phishing }
    | LegitDomain -> indicator
```

### Computation Expression (Signal Builder)
```fsharp
type SignalBuilder() =
    member _.Bind(x, f) = 
        match x with
        | Some value -> f value
        | None -> None
    member _.Return(x) = Some x
    member _.Zero() = None

let signal = SignalBuilder()

// Usage
let result = signal {
    let! indicator = findIndicator "185.220.101.45"
    let! enriched = enrichIndicator indicator
    return correlate enriched
}
```

### Pipeline Composition
```fsharp
let correlate (indicators: Indicator list) =
    defaultRules
    |> List.map (fun rule -> matchRule rule indicators)
    |> List.choose (function
        | SignalFound signal -> Some signal
        | _ -> None)
    |> List.sortByDescending (fun s -> Severity.toInt s.AggregatedSeverity)
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│               FSharpSignal Architecture                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│   ┌──────────────────┐                                        │
│   │  IOC Input       │  (IP, Domain, Hash, URL, Email)        │
│   └────────┬─────────┘                                        │
│            │                                                   │
│            ▼                                                   │
│   ┌──────────────────┐                                        │
│   │  Type Inference  │  Discriminated Unions                  │
│   │  & Validation    │  Active Patterns                       │
│   └────────┬─────────┘                                        │
│            │                                                   │
│            ▼                                                   │
│   ┌──────────────────┐                                        │
│   │  Enrichment      │  IP → GeoIP, ASN                       │
│   │  Pipeline        │  Hash → Malware DB                     │
│   │  (List.map)      │  Domain → Classification               │
│   └────────┬─────────┘                                        │
│            │                                                   │
│            ▼                                                   │
│   ┌──────────────────────────────────────────────────┐        │
│   │           Correlation Engine                      │        │
│   │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │        │
│   │  │ APT Rules   │ │ C2 Rules    │ │ Phish Rules │ │        │
│   │  └─────────────┘ └─────────────┘ └─────────────┘ │        │
│   │                Pattern Matching                   │        │
│   └────────────────────────┬─────────────────────────┘        │
│                            │                                   │
│                            ▼                                   │
│   ┌──────────────────┐    ┌──────────────────┐               │
│   │  Result Type     │    │  Report          │               │
│   │  SignalFound     │───▶│  Generation      │               │
│   │  NoMatch         │    │                  │               │
│   │  InsufficientData│    └──────────────────┘               │
│   └──────────────────┘                                        │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Why F#?

| Requirement | F# Advantage |
|-------------|--------------|
| Correctness | Exhaustive pattern matching |
| Immutability | Default immutable data |
| Composition | Function pipelines |
| Type Safety | Discriminated unions |
| Conciseness | Type inference |
| .NET Ecosystem | Full interoperability |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related Tools

- [nullsec-flowtrace](https://github.com/bad-antics/nullsec-flowtrace) - Flow analyzer (Haskell)
- [nullsec-cppsentry](https://github.com/bad-antics/nullsec-cppsentry) - Packet sentinel (C++)
- [nullsec-juliaprobe](https://github.com/bad-antics/nullsec-juliaprobe) - Anomaly detector (Julia)
