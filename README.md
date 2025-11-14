# Cybersecurity: Target Identification, Reconnaissance & Asset Discovery

---

## Table of Contents

- [Introduction to Target Identification](#introduction-to-target-identification)
- [Core Concepts](#core-concepts)
  - [Target vs. Asset vs. Vulnerability](#target-vs-asset-vs-vulnerability)
  - [Attack Surface](#attack-surface)
- [Primary Target Categories](#primary-target-categories)
- [Scoped vs. Discovered Targets](#scoped-vs-discovered-targets)
- [Target Prioritization](#target-prioritization)
- [Reconnaissance Fundamentals](#reconnaissance-fundamentals)
  - [The Intelligence Cycle](#the-intelligence-cycle-in-cybersecurity)
  - [Passive vs Active Reconnaissance](#passive-vs-active-reconnaissance-strategic-comparison)
  - [Reconnaissance Workflow](#systematic-reconnaissance-workflow)
  - [Tool Selection](#tool-categories-and-selection)
- [Asset Discovery](#asset-discovery)
  - [Client-Provided vs. Discovered Assets](#client-provided-vs-discovered-assets)
  - [Domain & DNS Enumeration](#domain-identification-and-analysis)
  - [Subdomain Enumeration](#subdomain-enumeration-expanding-the-attack-surface)
  - [Infrastructure Footprinting](#infrastructure-footprinting-connecting-the-dots)
  - [Shodan: Internet-Wide Asset Discovery](#shodan-internet-wide-asset-discovery)
  - [Discovery Workflow](#comprehensive-asset-discovery-workflow)
- [Organizational Information Harvesting](#organizational-information-harvesting)
  - [Business & Personnel Intelligence](#business-intelligence-gathering)
  - [Physical Intelligence](#physical-intelligence-and-location-analysis)
  - [Social Media & Job Posting Intelligence](#social-media-and-cultural-intelligence)
  - [Intelligence Collection Workflow](#comprehensive-organizational-intelligence-workflow)
- [Lab & Challenges](#asset-discovery-lab)
- [Summary & Key Takeaways](#summary)

---

## Introduction to Target Identification

> **Target identification** is a systematic, professional process—not random. It defines the scope, boundaries, and approach of security assessments.

---

## Core Concepts

### What is a Target?

A **target** in penetration testing is any asset (system, service, application, or human element) potentially leveraged for unauthorized access or privilege escalation.

> _In cybersecurity, "targets" differ from military/law enforcement contexts. Penetration targets are typically not adversarial in nature._

---

### Think About This

> Consider an organization:  
> What assets are most valuable or at greatest risk?  
> How might an attacker view your environment differently?

---

### Target vs. Asset vs. Vulnerability

| Concept        | Description                                                                                   |
| -------------- | ---------------------------------------------------------------------------------------------|
| **Asset**      | Anything of value to an organization—servers, applications, data, people, infrastructure, IP.|
| **Target**     | Assets viewed via attacker lens; potential entry points or resources to be compromised.       |
| **Vulnerability** | Weaknesses in targets exploitable for unauthorized access.                                 |
| **Attack Surface** | All accessible targets and their interconnections.                                        |

---

## Primary Target Categories

- **Technical Infrastructure Targets**  
  - *Network Infrastructure*: Routers, switches, firewalls
  - *Server Systems*: Databases, file servers

- **Application and Service Targets**  
  - *Web Applications*: Custom apps, external services

- **Human Element Targets**  
  - *Personnel*: Credentials, social engineering risk

- **Physical Infrastructure Targets**  
  - *Facilities*: Office, data centers

---

## Scoped vs. Discovered Targets

- **Explicitly Scoped**: Authorized for testing (from agreements).  
- **Discoverable**: Found during recon, requiring verification & added authorization.

---

## Target Prioritization

_Focus on the most critical assets:_

- Risk assessment required with client
- Cover all provided targets & systematically reveal others
- Prioritize publicly exposed or easily exploitable assets

---

## Reconnaissance Fundamentals

> Reconnaissance transforms the unknown into the known, guiding testing focus and strategy.

### The Intelligence Cycle in Cybersecurity

1. **Planning & Direction**: Define requirements, priorities, scope.
2. **Collection**: Gather information (passive/active).
3. **Processing & Analysis**: Validate, correlate, identify patterns.
4. **Dissemination & Feedback**: Document intelligence, refine strategy.

---

### Passive Reconnaissance

- **No direct interaction**
- Uses publicly available sources
- Undetectable, legal, comprehensive but may lack details

**Examples:**  
- OSINT sources: search engines, social media, public records

### Active Reconnaissance

- **Direct interaction with targets**
- Real-time intel, more detail
- Detectable, riskier, may trigger alerts

**Examples:**  
- Port scanning, service enumeration, banner grabbing

---

### Passive vs Active Reconnaissance: Strategic Comparison

| Method      | Advantages                    | Disadvantages                   |
| ----------- | ---------------------------- | ------------------------------- |
| Passive     | Undetectable, legal, broad   | May lack technical detail, outdated |
| Active      | Real time, technical detail  | Detectable, higher risk, needs permission |

---

### Systematic Reconnaissance Workflow

1. **Planning & Preparation**
   - Define requirements, scope, select tools
2. **Passive Intelligence Collection**
   - OSINT, public records, social media
3. **Active Intelligence Validation**
   - Service & vulnerability discovery
4. **Analysis and Reporting**
   - Pattern identification, risk prioritization

---

### Tool Categories and Selection

- **Passive Tools**: subfinder, amass (passive), Google, crt.sh
- **Active Tools**: amass (active), port scanners, DNS brute-force, Shodan CLI

---

## Asset Discovery

### Mapping the Digital Infrastructure

Identify & catalog digital assets: domains, subdomains, IP ranges, infrastructure.

---

### Client-Provided vs. Discovered Assets

- **Provided**: Directly from client; verified & scoped
- **Discovered**: Found via reconnaissance; requires approval

---

### Domain Identification and Analysis

- **Google searches** (`site:company.com`)
- **WHOIS lookups**
- **Certificate transparency** (crt.sh)
- **Advanced search operators** for hidden assets

---

### DNS Enumeration

- **DNS Record Types**: A, AAAA, MX, TXT, NS, SOA
- **Tools**: `dig` and `nslookup`
  - Zone transfer attempts: `dig @ns1.example.com example.com AXFR`
  - Reverse lookups: `dig -x {IP}`

---

### Subdomain Enumeration: Expanding the Attack Surface

_**Passive**_: crt.sh, subfinder, amass (passive)  
_**Active**_: amass (active), assetfinder, brute-force via common subdomain lists

---

### Infrastructure Footprinting: Connecting the Dots

- IP-to-domain mapping: `dig -x {IP}`
- Network mapping: WHOIS NetRange, CIDR, organization
- Hosting relationship analysis: shared hosting detection

---

### Shodan: Internet-Wide Asset Discovery

Visualizes all devices and services accessible on the web.

- **Queries**: by tech stack, org, IP, or service
- **CLI & API**: automation & historical data

---

### Comprehensive Asset Discovery Workflow

`bash
# Phase 1: Initial Identification
whois example.com
dig example.com NS

# Phase 2: Passive Discovery
curl crt.sh
subfinder/amass

# Phase 3: DNS & Infra Analysis
dig subdomain A MX TXT

# Phase 4: Active Validation
amass active
shodan search
`

---

### Asset Inventory Management

- **Validate scope**
- **Prioritize based on risk**
- **Map attack surface**
- **Document thoroughly**

---

## Asset Discovery Lab

> **Hub Challenge**: Practice DNS, subdomain, and asset discovery techniques.

### Challenge Tasks

1. DNS Dig
2. DNS Nslookup
3. DNS Zone Transfer
4. Subfinder
5. Amass
6. Shodan

> _Refer to your Kali training shell; follow steps in the Asset Discovery section._

---

## Organizational Information Harvesting

### The Human Intelligence Layer

Complement technical discovery with human & business context.

---

### Business Intelligence Gathering

- Corporate structure, subsidiaries, financial info
- Registration & ownership analysis, cross-referencing domains via WHOIS
- Use business registry databases (`site:sec.gov`, `site:crunchbase.com`)

---

### Personnel and Email Intelligence

- **Email harvesting**: `theHarvester`
- **Email validation**: `h8mail`
- **Naming convention analysis** & possible email pattern generation
- **Professional network intel**: LinkedIn searches to identify roles/skills

---

### Physical Intelligence and Location Analysis

- Facility addresses, data centers, security measures via Google Maps and Street View
- Wireless network analysis (wigle.net), social media check-ins

---

### Social Media and Cultural Intelligence

- Analyze official and employee accounts on Twitter, Facebook, Instagram, YouTube
- Physical/office tour videos for layout and security observations

---

### Job Posting Intelligence

> _Reveal technology stacks and critical org details from job postings on LinkedIn, Indeed, Glassdoor._

---

### Comprehensive Organizational Intelligence Workflow

`bash
# Phase 1: Corp Structure
whois example.com
site:sec.gov "Company Name" filings

# Phase 2: Personnel
theHarvester -d example.com
LinkedIn search

# Phase 3: Physical
Google Maps
wigle.net wireless queries

# Phase 4: Tech/Culture
Indeed/LinkedIn job searches
Social media scans
`

---

## Summary & Key Takeaways

- **Target identification** sets scope, boundaries, and approach.
- **Reconnaissance**: strategic intelligence collection transforms unknowns to actionable targets.
- **Asset discovery**: exposes real attack surface—not just what clients provide.
- **Organizational intel**: business and human context are essential for a complete security picture.
- **Systematic workflows & documentation**: critical at each stage.

---

> **Keep learning, stay curious, and confirm scope at every stage!**
