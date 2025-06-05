# Medical Device CVSS Calculator

A React TypeScript application that adapts the standard CVSS v3.1 vulnerability scoring system for medical device security assessment. Provides both a guided questionnaire interface for non-technical users and a technical calculator interface for cybersecurity professionals.

## Features

- **Guided Questionnaire**: Medical device-specific scenarios with customizable questions
- **Technical Calculator**: Complete CVSS v3.1 metric selection interface
- **Real-time Calculation**: Instant score updates with severity ratings
- **Vector String Generation**: Standards-compliant CVSS vector output
- **Responsive Design**: Works on desktop and mobile devices

## Quick Start

```bash
cd med-cvss-calculator
npm install
npm start
```

Navigate to http://localhost:3000 to access the application.

## Usage

1. **Questionnaire Mode** (`/questionnaire`): Answer medical device-specific questions to generate CVSS scores
2. **Calculator Mode** (`/calculator`): Directly select CVSS metrics for technical assessment

## Technology Stack

- React 19.1.0 with TypeScript
- React Router DOM for navigation
- CSS3 with gradient styling
- localStorage for data persistence

## CVSS Compliance

Implements the complete CVSS v3.1 specification including Base, Temporal, and Environmental metrics with official scoring algorithms.