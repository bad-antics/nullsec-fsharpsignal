// NullSec FSharpSignal - Threat Signal Correlator
// Cross-platform threat intelligence correlation engine
// F# - Functional-first programming with type safety

open System
open System.Collections.Generic
open System.Security.Cryptography
open System.Text
open System.Text.RegularExpressions

// =============================================================================
// Domain Types - Discriminated Unions & Records
// =============================================================================

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

type ThreatCategory =
    | Malware
    | Phishing
    | C2Infrastructure
    | DataExfiltration
    | LateralMovement
    | PrivilegeEscalation
    | InitialAccess
    | Persistence

type ConfidenceLevel =
    | Confirmed
    | HighConfidence
    | MediumConfidence
    | LowConfidence
    | Unverified

type Indicator = {
    Id: Guid
    Type: IndicatorType
    Value: string
    Category: ThreatCategory
    Severity: Severity
    Confidence: ConfidenceLevel
    Source: string
    FirstSeen: DateTime
    LastSeen: DateTime
    Tags: string list
    MitreIds: string list
}

type CorrelationRule = {
    Name: string
    Description: string
    RequiredTypes: IndicatorType list
    MinMatches: int
    TimeWindowMinutes: int
    OutputSeverity: Severity
    MitreMapping: string
}

type CorrelatedSignal = {
    RuleName: string
    Indicators: Indicator list
    AggregatedSeverity: Severity
    CorrelationTime: DateTime
    Score: float
    MitreAttackId: string
}

type AnalysisResult =
    | SignalFound of CorrelatedSignal
    | NoMatch
    | InsufficientData of string

// =============================================================================
// Pattern Matching & Active Patterns
// =============================================================================

let (|IPv4|IPv6|InvalidIP|) (value: string) =
    let ipv4Pattern = @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    let ipv6Pattern = @"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$"
    if Regex.IsMatch(value, ipv4Pattern) then IPv4
    elif Regex.IsMatch(value, ipv6Pattern) then IPv6
    else InvalidIP

let (|KnownMalwareHash|SuspiciousHash|CleanHash|) (hash: string) =
    let knownBadHashes = [
        "44d88612fea8a8f36de82e1278abb02f"  // EICAR
        "e99a18c428cb38d5f260853678922e03"  // Known malware
        "098f6bcd4621d373cade4e832627b4f6"  // Test hash
    ]
    if List.contains (hash.ToLowerInvariant()) knownBadHashes then KnownMalwareHash
    elif hash.Length = 32 || hash.Length = 40 || hash.Length = 64 then SuspiciousHash
    else CleanHash

let (|C2Domain|PhishingDomain|LegitDomain|) (domain: string) =
    let c2Patterns = [".onion"; ".bit"; "duckdns.org"; "no-ip.com"; "ddns.net"]
    let phishingKeywords = ["login"; "secure"; "update"; "verify"; "account"]
    let lowerDomain = domain.ToLowerInvariant()
    if c2Patterns |> List.exists (fun p -> lowerDomain.EndsWith(p)) then C2Domain
    elif phishingKeywords |> List.exists (fun k -> lowerDomain.Contains(k)) then PhishingDomain
    else LegitDomain

// =============================================================================
// Computation Expressions - Signal Builder
// =============================================================================

type SignalBuilder() =
    member _.Bind(x, f) = 
        match x with
        | Some value -> f value
        | None -> None
    
    member _.Return(x) = Some x
    member _.ReturnFrom(x) = x
    member _.Zero() = None
    
    member _.Combine(a, b) =
        match a with
        | Some _ -> a
        | None -> b()
    
    member _.Delay(f) = f

let signal = SignalBuilder()

// =============================================================================
// Higher-Order Functions & Pipelines
// =============================================================================

module Severity =
    let toInt = function
        | Critical -> 5
        | High -> 4
        | Medium -> 3
        | Low -> 2
        | Informational -> 1

    let toString = function
        | Critical -> "CRITICAL"
        | High -> "HIGH"
        | Medium -> "MEDIUM"
        | Low -> "LOW"
        | Informational -> "INFO"

    let max sev1 sev2 =
        if toInt sev1 > toInt sev2 then sev1 else sev2

module Indicator =
    let create iocType value category severity confidence source tags mitre =
        {
            Id = Guid.NewGuid()
            Type = iocType
            Value = value
            Category = category
            Severity = severity
            Confidence = confidence
            Source = source
            FirstSeen = DateTime.UtcNow
            LastSeen = DateTime.UtcNow
            Tags = tags
            MitreIds = mitre
        }
    
    let updateLastSeen indicator =
        { indicator with LastSeen = DateTime.UtcNow }
    
    let addTag tag indicator =
        { indicator with Tags = tag :: indicator.Tags }
    
    let matchesType indicatorType indicator =
        indicator.Type = indicatorType
    
    let isHighSeverity indicator =
        match indicator.Severity with
        | Critical | High -> true
        | _ -> false

// =============================================================================
// Correlation Engine - Functional Core
// =============================================================================

module CorrelationEngine =
    
    let defaultRules : CorrelationRule list = [
        {
            Name = "APT Campaign Detection"
            Description = "Multiple indicators from same campaign"
            RequiredTypes = [IPAddress; Domain; FileHash]
            MinMatches = 3
            TimeWindowMinutes = 60
            OutputSeverity = Critical
            MitreMapping = "TA0001"
        }
        {
            Name = "C2 Infrastructure"
            Description = "Command and control communication patterns"
            RequiredTypes = [IPAddress; Domain]
            MinMatches = 2
            TimeWindowMinutes = 30
            OutputSeverity = High
            MitreMapping = "T1071"
        }
        {
            Name = "Lateral Movement"
            Description = "Internal network traversal indicators"
            RequiredTypes = [IPAddress; ProcessName]
            MinMatches = 2
            TimeWindowMinutes = 15
            OutputSeverity = High
            MitreMapping = "TA0008"
        }
        {
            Name = "Data Staging"
            Description = "Preparation for exfiltration"
            RequiredTypes = [FileHash; ProcessName; Registry]
            MinMatches = 2
            TimeWindowMinutes = 45
            OutputSeverity = Medium
            MitreMapping = "T1074"
        }
        {
            Name = "Phishing Infrastructure"
            Description = "Phishing campaign indicators"
            RequiredTypes = [Domain; Email; URL]
            MinMatches = 2
            TimeWindowMinutes = 120
            OutputSeverity = Medium
            MitreMapping = "T1566"
        }
    ]
    
    let calculateScore (indicators: Indicator list) : float =
        indicators
        |> List.map (fun i -> 
            let severityScore = float (Severity.toInt i.Severity)
            let confidenceMultiplier = 
                match i.Confidence with
                | Confirmed -> 1.0
                | HighConfidence -> 0.9
                | MediumConfidence -> 0.7
                | LowConfidence -> 0.4
                | Unverified -> 0.2
            severityScore * confidenceMultiplier)
        |> List.average
        |> (*) (float (List.length indicators))
        |> min 100.0
    
    let aggregateSeverity (indicators: Indicator list) : Severity =
        indicators
        |> List.map (fun i -> i.Severity)
        |> List.fold Severity.max Informational
    
    let checkTimeWindow (windowMinutes: int) (indicators: Indicator list) : bool =
        match indicators with
        | [] -> false
        | [_] -> true
        | indicators ->
            let times = indicators |> List.map (fun i -> i.FirstSeen)
            let minTime = List.min times
            let maxTime = List.max times
            (maxTime - minTime).TotalMinutes <= float windowMinutes
    
    let matchRule (rule: CorrelationRule) (indicators: Indicator list) : AnalysisResult =
        let matchingByType =
            rule.RequiredTypes
            |> List.map (fun rt -> 
                indicators |> List.filter (Indicator.matchesType rt))
            |> List.filter (fun matches -> not (List.isEmpty matches))
        
        if List.length matchingByType < rule.MinMatches then
            InsufficientData $"Need {rule.MinMatches} indicator types, found {List.length matchingByType}"
        else
            let allMatching = matchingByType |> List.concat
            if checkTimeWindow rule.TimeWindowMinutes allMatching then
                SignalFound {
                    RuleName = rule.Name
                    Indicators = allMatching
                    AggregatedSeverity = aggregateSeverity allMatching |> Severity.max rule.OutputSeverity
                    CorrelationTime = DateTime.UtcNow
                    Score = calculateScore allMatching
                    MitreAttackId = rule.MitreMapping
                }
            else
                InsufficientData "Indicators outside time window"
    
    let correlate (indicators: Indicator list) : CorrelatedSignal list =
        defaultRules
        |> List.map (fun rule -> matchRule rule indicators)
        |> List.choose (function
            | SignalFound signal -> Some signal
            | _ -> None)
        |> List.sortByDescending (fun s -> Severity.toInt s.AggregatedSeverity)

// =============================================================================
// Enrichment Pipeline - Async Workflows
// =============================================================================

module Enrichment =
    
    let enrichIP (indicator: Indicator) : Indicator =
        match indicator.Value with
        | IPv4 ->
            indicator 
            |> Indicator.addTag "ipv4"
            |> Indicator.addTag "routable"
        | IPv6 ->
            indicator 
            |> Indicator.addTag "ipv6"
        | InvalidIP ->
            indicator 
            |> Indicator.addTag "invalid-format"
    
    let enrichHash (indicator: Indicator) : Indicator =
        match indicator.Value with
        | KnownMalwareHash ->
            { indicator with 
                Severity = Critical
                Confidence = Confirmed
                Tags = "known-malware" :: indicator.Tags }
        | SuspiciousHash ->
            indicator |> Indicator.addTag "valid-hash"
        | CleanHash ->
            indicator |> Indicator.addTag "invalid-hash-format"
    
    let enrichDomain (indicator: Indicator) : Indicator =
        match indicator.Value with
        | C2Domain ->
            { indicator with
                Category = C2Infrastructure
                Severity = Severity.max indicator.Severity High
                Tags = "c2-infrastructure" :: indicator.Tags }
        | PhishingDomain ->
            { indicator with
                Category = Phishing
                Tags = "phishing-keywords" :: indicator.Tags }
        | LegitDomain ->
            indicator
    
    let enrichIndicator (indicator: Indicator) : Indicator =
        match indicator.Type with
        | IPAddress -> enrichIP indicator
        | FileHash -> enrichHash indicator
        | Domain | URL -> enrichDomain indicator
        | _ -> indicator
    
    let enrichAll (indicators: Indicator list) : Indicator list =
        indicators |> List.map enrichIndicator

// =============================================================================
// Report Generation - String Interpolation
// =============================================================================

module Report =
    
    let private severityColor severity =
        match severity with
        | Critical -> "\x1b[91m"  // Red
        | High -> "\x1b[93m"       // Yellow
        | Medium -> "\x1b[33m"     // Orange
        | Low -> "\x1b[94m"        // Blue
        | Informational -> "\x1b[90m"  // Gray
    
    let private reset = "\x1b[0m"
    
    let formatIndicator (indicator: Indicator) : string =
        let typeStr = 
            match indicator.Type with
            | IPAddress -> "IP"
            | Domain -> "Domain"
            | FileHash -> "Hash"
            | URL -> "URL"
            | Email -> "Email"
            | Registry -> "Registry"
            | ProcessName -> "Process"
            | Mutex -> "Mutex"
        
        let color = severityColor indicator.Severity
        $"      {color}[{Severity.toString indicator.Severity}]{reset} {typeStr}: {indicator.Value}"
    
    let formatSignal (signal: CorrelatedSignal) : string =
        let color = severityColor signal.AggregatedSeverity
        let indicators = 
            signal.Indicators 
            |> List.map formatIndicator 
            |> String.concat "\n"
        
        $"""
  {color}╔═══════════════════════════════════════════════════════════════╗
  ║  CORRELATED SIGNAL: {signal.RuleName,-40} ║
  ╚═══════════════════════════════════════════════════════════════╝{reset}
    
    Severity:     {color}{Severity.toString signal.AggregatedSeverity}{reset}
    Score:        {signal.Score:F1}/100
    MITRE ID:     {signal.MitreAttackId}
    Correlation:  {signal.CorrelationTime:yyyy-MM-dd HH:mm:ss} UTC
    
    Indicators:
{indicators}
"""
    
    let generateReport (signals: CorrelatedSignal list) : string =
        let header = """
╔══════════════════════════════════════════════════════════════════╗
║        NullSec FSharpSignal - Threat Signal Correlator           ║
╚══════════════════════════════════════════════════════════════════╝
"""
        let body = 
            if List.isEmpty signals then
                "\n  No correlated signals detected.\n"
            else
                signals 
                |> List.map formatSignal 
                |> String.concat "\n"
        
        let summary = 
            let criticalCount = signals |> List.filter (fun s -> s.AggregatedSeverity = Critical) |> List.length
            let highCount = signals |> List.filter (fun s -> s.AggregatedSeverity = High) |> List.length
            let mediumCount = signals |> List.filter (fun s -> s.AggregatedSeverity = Medium) |> List.length
            let totalScore = signals |> List.sumBy (fun s -> s.Score)
            $"""
═══════════════════════════════════════════════════════════════════

  Summary:
    Total Signals:    {List.length signals}
    Critical:         \x1b[91m{criticalCount}\x1b[0m
    High:             \x1b[93m{highCount}\x1b[0m
    Medium:           \x1b[33m{mediumCount}\x1b[0m
    Combined Score:   {totalScore:F1}
"""
        
        header + body + summary

// =============================================================================
// Demo Data - Sample Threat Intelligence
// =============================================================================

module Demo =
    
    let sampleIndicators : Indicator list = [
        // APT Campaign indicators
        Indicator.create IPAddress "185.220.101.45" C2Infrastructure High HighConfidence "ThreatFeed-A" ["apt"; "cobalt-strike"] ["T1071.001"]
        Indicator.create Domain "update-service.duckdns.org" C2Infrastructure High MediumConfidence "ThreatFeed-A" ["apt"; "dga"] ["T1071.004"]
        Indicator.create FileHash "44d88612fea8a8f36de82e1278abb02f" Malware Critical Confirmed "VirusTotal" ["malware"; "trojan"] ["T1204"]
        
        // Lateral movement indicators
        Indicator.create IPAddress "10.0.0.100" LateralMovement Medium MediumConfidence "EDR" ["internal"; "suspicious"] ["T1021"]
        Indicator.create ProcessName "psexec.exe" LateralMovement High HighConfidence "EDR" ["lolbin"; "admin-tool"] ["T1570"]
        
        // Phishing indicators
        Indicator.create Domain "secure-login-verify.com" Phishing Medium MediumConfidence "PhishTank" ["phishing"; "credential-theft"] ["T1566.002"]
        Indicator.create Email "support@secure-login-verify.com" Phishing Medium LowConfidence "UserReport" ["phishing"] ["T1566.001"]
        Indicator.create URL "https://secure-login-verify.com/login.php" Phishing High MediumConfidence "URLScan" ["phishing"; "credential-harvest"] ["T1566.002"]
        
        // Additional C2
        Indicator.create IPAddress "45.33.32.156" C2Infrastructure Medium MediumConfidence "ThreatFeed-B" ["scanner"; "recon"] ["T1595"]
        Indicator.create Domain "c2-beacon.no-ip.com" C2Infrastructure High HighConfidence "ThreatFeed-B" ["c2"; "beacon"] ["T1071.001"]
        
        // Data staging
        Indicator.create FileHash "e99a18c428cb38d5f260853678922e03" DataExfiltration High MediumConfidence "Sandbox" ["staging"; "archive"] ["T1074.001"]
        Indicator.create ProcessName "7z.exe" DataExfiltration Medium LowConfidence "EDR" ["compression"; "staging"] ["T1560.001"]
        Indicator.create Registry @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" Persistence Medium MediumConfidence "EDR" ["persistence"; "autorun"] ["T1547.001"]
    ]

// =============================================================================
// Entry Point
// =============================================================================

[<EntryPoint>]
let main argv =
    printfn ""
    printfn "╔══════════════════════════════════════════════════════════════════╗"
    printfn "║        NullSec FSharpSignal - Threat Signal Correlator           ║"
    printfn "╚══════════════════════════════════════════════════════════════════╝"
    printfn ""
    printfn "[Demo Mode]"
    printfn ""
    printfn "Loading threat intelligence indicators..."
    printfn ""
    
    // Enrich indicators
    let enrichedIndicators = 
        Demo.sampleIndicators 
        |> Enrichment.enrichAll
    
    printfn "  Loaded %d indicators" (List.length enrichedIndicators)
    printfn ""
    printfn "Running correlation engine..."
    printfn ""
    
    // Correlate signals
    let signals = CorrelationEngine.correlate enrichedIndicators
    
    // Generate and print report
    let report = Report.generateReport signals
    printfn "%s" report
    
    // Print indicator summary
    printfn "  Indicator Breakdown:"
    let byType = enrichedIndicators |> List.groupBy (fun i -> i.Type)
    for (iocType, indicators) in byType do
        let typeStr = 
            match iocType with
            | IPAddress -> "IP Addresses"
            | Domain -> "Domains"
            | FileHash -> "File Hashes"
            | URL -> "URLs"
            | Email -> "Emails"
            | ProcessName -> "Processes"
            | Registry -> "Registry Keys"
            | Mutex -> "Mutexes"
        printfn "    %-15s %d" typeStr (List.length indicators)
    
    printfn ""
    printfn "═══════════════════════════════════════════════════════════════════"
    printfn ""
    
    0
