# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The `med-cvss` repository contains a **Medical Device CVSS Calculator** - a React TypeScript application that implements both CVSS v3.1 and v4.0 vulnerability scoring systems for medical device security assessment. The application provides both a guided questionnaire interface for non-technical users and a technical calculator interface for cybersecurity professionals.

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

# Single test execution
npm test -- --testNamePattern="specific test name"
npm test -- --testPathPattern="filename pattern"
```

## Architecture Overview

**Component Architecture:**
- **IntegratedCVSSCalculator**: Main CVSS calculator with support for both v3.1 and v4.0
- **ThreatAnalysis**: AI-powered threat assessment from Japanese descriptions (MCP)
- **CVSSComparison**: Before/after vulnerability assessment with remediation tracking
- **MitreCVSSRubric**: MITRE medical device decision tree implementation
- **ScenarioEditor**: Create/edit custom medical device vulnerability scenarios
- **Authentication Components**: Login, Signup, ProtectedRoute, Navigation with Firebase Auth

**Data Flow:**
1. **Manual Assessment**: User selects CVSS version (v3.1 or v4.0) and metrics through UI components
2. **AI Assessment**: Japanese threat descriptions are analyzed via MCP to extract CVSS metrics
3. Real-time calculation using version-specific algorithms (`cvssCalculator.ts` for v3.1, `cvssV4Calculator.ts` for v4.0)
4. Results display score, severity rating, and vector string for chosen version
5. Optional persistence to localStorage or Firebase Firestore
6. Export/import scenarios for team collaboration

**Key Directories:**
- `src/components/` - React components with component-scoped CSS
- `src/data/` - CVSS metrics, medical device guidance, MITRE rubric data
- `src/utils/` - CVSS calculation algorithms and comparison logic
- `src/types/` - TypeScript interfaces for type safety
- `src/hooks/` - Custom React hooks for scenario management
- `src/services/` - Firebase configuration, MCP client, and storage services
- `src/contexts/` - React contexts for authentication

## CVSS Implementation

The application implements both CVSS v3.1 and v4.0 specifications with seamless version switching:

**CVSS v3.1 Features:**
- **Base Metrics**: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability Impact
- **Temporal Metrics**: Exploit Code Maturity, Remediation Level, Report Confidence

**CVSS v4.0 Features:**
- **Base Metrics**: Attack Vector, Attack Complexity, Attack Requirements, Privileges Required, User Interaction, Vulnerable/Subsequent System Impact (C/I/A)
- **Threat Metrics**: Exploit Maturity
- **Environmental Metrics**: Confidentiality/Integrity/Availability Requirements
- **Supplemental Metrics**: Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort, Provider Urgency

Key implementation files:
- `cvssCalculator.ts`: CVSS v3.1 scoring algorithms and vector string generation
- `cvssV4Calculator.ts`: CVSS v4.0 scoring algorithms and equivalence classes
- `cvssV4FullImplementation.ts`: Full CVSS v4.0 implementation with official algorithm
- `cvssComparison.ts`: Before/after comparison calculations
- `cvssMetrics.ts`: CVSS v3.1 metric definitions with scores
- `cvssV4Metrics.ts`: CVSS v4.0 metric definitions with scores
- `remediationGuidance.ts`: Medical device-specific remediation recommendations
- `mcpClient.ts`: MCP (Model Context Protocol) client for AI threat extraction

## Medical Device Focus

The application is specifically designed for healthcare contexts with:
- Pre-built scenarios for common medical devices (infusion pumps, Bluetooth devices, etc.)
- Patient data protection impact assessments
- Medical device availability considerations
- Healthcare integrity impact evaluations
- MITRE decision flow for medical device CVSS assessment
- Remediation guidance tailored to healthcare environments
- AI-powered threat analysis optimized for Japanese medical device vulnerabilities

## State Management

- Local component state using React hooks
- Storage options:
  - localStorage (default): `useCustomScenarios('localStorage')`
  - Firebase Firestore: `useCustomScenarios('firebase', userId)`
- Navigation state for passing data between components
- Firebase Authentication context for user management
- MCP connection state for AI threat analysis
- No external state management library (Redux, Zustand) currently used

## Testing Strategy

- Jest with React Testing Library
- Coverage thresholds: 70% global, 80% for utils, 60% for data
- Test files in `src/__tests__/` directory
- Key test suites:
  - `cvssCalculator.test.ts`: CVSS v3.1 algorithm validation
  - `cvssV4Calculator.test.ts`: CVSS v4.0 algorithm validation
  - `cvssV4Debug.test.ts`: CVSS v4.0 debug and edge cases
  - `cvssV4Official.test.ts`: CVSS v4.0 official implementation validation
  - `cvssComparison.test.ts`: Before/after logic
  - `mitre-decision-flow.test.ts`: MITRE rubric testing
  - `mitre-cia-flow.test.ts`: CIA impact assessment

## MCP Integration (Model Context Protocol)

The application integrates with the [med-mcp-threat server](https://github.com/osamusic/med-mcp-threat) for AI-powered threat analysis:

**Architecture:**
- `mcpClient.ts`: MCP client service for communicating with threat extraction server
- `ThreatAnalysis.tsx`: React component providing single and batch threat analysis
- Connection detection via `window.use_mcp_tool` function availability
- Real-time connection status display with fallback handling

**Key Features:**
- Japanese medical device threat description processing
- Automatic CVSS v3.1 metric extraction from natural language
- Batch processing for multiple threats simultaneously
- Integration with existing CVSS calculator via navigation state

**Environment Variables:**
```bash
REACT_APP_MCP_ENABLED=true
REACT_APP_MCP_THREAT_SERVER=threat-extraction
```

**Requirements:**
- Claude Desktop with MCP support
- med-mcp-threat server configured
- User authentication (protected route)

## Important Implementation Details

**Version Compatibility:**
- CVSS v3.1 and v4.0 use different metric sets - automatic reset when switching versions
- MITRE rubric (questionnaire mode) only available for CVSS v3.1
- Prefilled metrics from navigation state expand relevant sections automatically

**Authentication Flow:**
- ThreatAnalysis and CVSSComparison components are protected routes
- Firebase Auth with email/password and Google OAuth
- Conditional navigation rendering based on authentication state

**Data Persistence:**
- Scenarios stored with version-specific data structures
- localStorage fallback when Firebase unavailable
- Navigation state used for cross-component data passing (calculator prefill)

**Development Notes:**
- React 19 with TypeScript strict mode
- Component-scoped CSS (avoid global styles)
- Medical device guidance data drives UI help text
- Real-time CVSS calculation on metric selection
- Comprehensive test coverage for calculation algorithms

## Firebase Integration (Optional)

For cloud storage and authentication:
1. Create Firebase project with Firestore and Authentication enabled
2. Configure `.env.local` with Firebase credentials
3. Enable desired authentication providers (Email/Password, Google OAuth)
4. See `FIREBASE_SETUP.md` for detailed instructions