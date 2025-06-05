# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The `med-cvss` repository contains a **Medical Device CVSS Calculator** - a React TypeScript application that adapts the standard CVSS v3.1 vulnerability scoring system for medical device security assessment. The application provides both a guided questionnaire interface for non-technical users and a technical calculator interface for cybersecurity professionals.

## Development Commands

Navigate to the `med-cvss-calculator` directory before running these commands:

```bash
cd med-cvss-calculator

# Development
npm start              # Development server (localhost:3000)
npm test               # Run test suite in watch mode
npm run test:coverage  # Run tests with coverage report
npm run test:mitre     # Run MITRE decision flow tests specifically

# Code Quality
npm run lint           # ESLint check
npm run lint:fix       # Auto-fix linting issues
npm run format         # Prettier formatting
npm run format:check   # Check formatting without changes
npm run type-check     # TypeScript type checking
npm run quality        # Run all quality checks (type-check, lint, format, tests)

# Build
npm run build          # Production build to ./build directory

# Docker
docker-compose up -d med-cvss-calculator  # Production (port 3000)
docker-compose --profile dev up dev       # Development with hot reload (port 3001)
```

## Architecture Overview

**Component Architecture:**
- **IntegratedCVSSCalculator**: Main CVSS v3.1 calculator with technical interface
- **CVSSComparison**: Before/after vulnerability assessment with remediation tracking
- **MitreCVSSRubric**: MITRE medical device decision tree implementation
- **ScenarioEditor**: Create/edit custom medical device vulnerability scenarios
- **ScenarioImportExport**: Share scenarios between teams via JSON export/import

**Data Flow:**
1. User selects CVSS metrics through UI components
2. Real-time calculation using `cvssCalculator.ts` algorithms
3. Results display score, severity rating, and vector string
4. Optional persistence to localStorage or Firebase Firestore
5. Export/import scenarios for team collaboration

**Key Directories:**
- `src/components/` - React components with component-scoped CSS
- `src/data/` - CVSS metrics, medical device guidance, MITRE rubric data
- `src/utils/` - CVSS calculation algorithms and comparison logic
- `src/types/` - TypeScript interfaces for type safety
- `src/hooks/` - Custom React hooks for scenario management
- `src/services/` - Firebase configuration and storage services
- `src/contexts/` - React contexts for authentication

## CVSS Implementation

The application implements the full CVSS v3.1 specification including:
- **Base Metrics**: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability Impact
- **Temporal Metrics**: Exploit Code Maturity, Remediation Level, Report Confidence

Key implementation files:
- `cvssCalculator.ts`: Core scoring algorithms and vector string generation
- `cvssComparison.ts`: Before/after comparison calculations
- `cvssMetrics.ts`: Complete metric definitions with scores
- `remediationGuidance.ts`: Medical device-specific remediation recommendations

## Medical Device Focus

The application is specifically designed for healthcare contexts with:
- Pre-built scenarios for common medical devices (infusion pumps, Bluetooth devices, etc.)
- Patient data protection impact assessments
- Medical device availability considerations
- Healthcare integrity impact evaluations
- MITRE decision flow for medical device CVSS assessment
- Remediation guidance tailored to healthcare environments

## State Management

- Local component state using React hooks
- Storage options:
  - localStorage (default): `useCustomScenarios('localStorage')`
  - Firebase Firestore: `useCustomScenarios('firebase', userId)`
- Navigation state for passing data between components
- Firebase Authentication context for user management
- No external state management library (Redux, Zustand) currently used

## Testing Strategy

- Jest with React Testing Library
- Coverage thresholds: 70% global, 80% for utils, 60% for data
- Test files in `src/__tests__/` directory
- Key test suites:
  - `cvssCalculator.test.ts`: Algorithm validation
  - `cvssComparison.test.ts`: Before/after logic
  - `mitre-decision-flow.test.ts`: MITRE rubric testing
  - `mitre-cia-flow.test.ts`: CIA impact assessment

## Firebase Integration (Optional)

For cloud storage and authentication:
1. Create Firebase project with Firestore and Authentication enabled
2. Configure `.env.local` with Firebase credentials
3. Enable desired authentication providers (Email/Password, Google OAuth)
4. See `FIREBASE_SETUP.md` for detailed instructions