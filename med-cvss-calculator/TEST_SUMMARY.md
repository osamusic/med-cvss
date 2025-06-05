# MITRE Rubric Decision Flow Test Cases

## Overview

Created comprehensive test cases for MITRE medical device CVSS rubric decision flows, covering:
- **Attack Vector (AV)** decision tree logic
- **Confidentiality, Integrity, Availability (CIA)** parallel evaluation logic

## Test Results

✅ **All 28 test cases passed**

```
Test Suites: 2 passed, 2 total
Tests:       28 passed, 28 total
```

## Attack Vector (AV) Tests

### Decision Tree Flow
```
Q1: Network accessible? (XAVN)
├─ Yes → Q2: OSI 3/4 protocols? (XAVT)
│   ├─ Yes/Unknown → AV = Network (N)
│   └─ No → Q3: Wireless? (XAVW)
│       ├─ Yes → Q4: Range ≤10ft? (XAVR)
│       │   ├─ Yes → AV = Local (L)
│       │   └─ No/Unknown → AV = Adjacent (A)
│       └─ No → AV = Adjacent (A)
├─ No → Q5: Physical contact? (XAVP)
│   ├─ Yes → AV = Physical (P)
│   └─ No/Unknown → AV = Local (L)
└─ Unknown → AV = Network (N)
```

### Test Cases (12 total)
1. **Network via TCP/IP** → AV = Network (N)
2. **Bluetooth short range (≤10ft)** → AV = Local (L)
3. **WiFi long range (>10ft)** → AV = Adjacent (A)
4. **Physical access required** → AV = Physical (P)
5. **Local access (no network/physical)** → AV = Local (L)
6. **Unknown network accessibility** → AV = Network (N)
7. **Wired non-TCP/UDP** → AV = Adjacent (A)

### Medical Device Scenarios (5 total)
- **Internet-connected infusion pump** → AV = Network (N)
- **Bluetooth glucose monitor (close range)** → AV = Local (L)
- **WiFi patient monitor** → AV = Adjacent (A)
- **Implantable pacemaker** → AV = Physical (P)
- **USB diagnostic device** → AV = Local (L)

## CIA (Confidentiality, Integrity, Availability) Tests

### Parallel Evaluation Logic
Each metric evaluates 6 data categories:
1. **XCP/XIP/XAP**: PHI/PII data
2. **XCD/XID/XAD**: Diagnosis/monitoring data
3. **XCT/XIT/XAT**: Therapy delivery data
4. **XCW/XIW/XAW**: Clinical workflow data
5. **XCS/XIS/XAS**: Private system data
6. **XCO/XIO/XAO**: Other critical data

**Final Determination:**
- Any **High** → Overall **High**
- Else any **Low** → Overall **Low**
- Else → Overall **None**

### Confidentiality Tests (5 total)
- **Large scale PHI (500+)** → C = High
- **Small scale PHI (<500)** → C = Low
- **Multiple data types** → C = High
- **No exposure** → C = None
- **Unknown exposure** → C = High

### Integrity Tests (4 total)
- **PHI modification** → I = High
- **System data modification** → I = High
- **No modification** → I = None
- **Unknown modification** → I = High

### Availability Tests (3 total)
- **Therapy delivery disruption** → A = High
- **Multiple system disruptions** → A = High
- **No availability impact** → A = None

### Medical Device CIA Scenarios (4 total)
1. **Hospital EHR breach**: C=High, I=High, A=None
2. **Infusion pump DoS**: C=None, I=None, A=High
3. **Small clinic PHI only**: C=Low, I=None, A=None
4. **Small clinic with monitoring data**: C=High (any High = overall High)

## Key Test Insights

### Attack Vector Logic
- **Conservative defaults**: Unknown answers default to more severe ratings (Network)
- **Range-based wireless**: 10ft threshold distinguishes Local vs Adjacent
- **Protocol specificity**: OSI layer 3/4 protocols indicate true network accessibility

### CIA Logic
- **Any High rule**: Single High impact category elevates overall rating
- **Scale consideration**: Only Confidentiality considers patient count (500+ threshold)
- **Conservative unknowns**: Unknown answers treated as High impact
- **Medical context**: Categories reflect healthcare-specific data types

## Test Coverage

✅ **Decision tree branching** - All paths tested  
✅ **Edge cases** - Unknown answers, boundary conditions  
✅ **Medical scenarios** - Real-world device examples  
✅ **Logic validation** - Complex multi-criteria evaluation  
✅ **Scale sensitivity** - Patient count thresholds  

## Usage

Run tests with:
```bash
npm test -- --testPathPattern="mitre.*flow"
```

These tests validate the MITRE rubric implementation and can serve as regression tests for future updates to the decision flow logic.