# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The `med-cvss` repository contains a **Medical Device CVSS Calculator** - a React TypeScript application that adapts the standard CVSS v3.1 vulnerability scoring system for medical device security assessment. The application provides both a guided questionnaire interface for non-technical users and a technical calculator interface for cybersecurity professionals.

## Development Commands

Navigate to the `med-cvss-calculator` directory before running these commands:

```bash
cd med-cvss-calculator
npm start          # Development server (localhost:3000)
npm test           # Run test suite
npm run build      # Production build
```

## Architecture Overview

**Component Architecture:**
- **CVSSQuestionnaire**: Guided questionnaire with medical device scenarios, customizable questions stored in localStorage
- **CVSSCalculator**: Technical CVSS metric selection interface with real-time calculation
- **App**: Root component with React Router handling navigation between `/questionnaire` and `/calculator`

**Data Flow:**
1. Questionnaire collects user responses and maps to CVSS metrics
2. Navigation state passes selected values to calculator
3. Calculator performs real-time CVSS v3.1 calculations
4. Results display score, severity rating, and vector string

**Key Directories:**
- `src/components/` - React components (questionnaire and calculator UIs)
- `src/data/cvssMetrics.ts` - Complete CVSS v3.1 metric definitions with scores
- `src/utils/cvssCalculator.ts` - CVSS calculation algorithms and vector string generation
- `src/types/cvss.ts` - TypeScript interfaces for CVSS data structures

## CVSS Implementation

The application implements the full CVSS v3.1 specification including:
- **Base Metrics**: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability Impact
- **Temporal Metrics**: Exploit Code Maturity, Remediation Level, Report Confidence
- **Environmental Metrics**: Modified Base metrics and Confidentiality/Integrity/Availability Requirements

## Medical Device Focus

The questionnaire is specifically designed for healthcare contexts with:
- Patient data protection scenarios
- Medical device availability considerations  
- Healthcare integrity impact assessments
- Medical device-specific vulnerability examples

## State Management

- Local component state using React hooks
- localStorage for custom questionnaire questions
- Navigation state for passing data between components
- No external state management library (Redux, Zustand) currently used