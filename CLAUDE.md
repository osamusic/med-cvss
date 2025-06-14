# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The `med-cvss` repository contains a **Medical Device CVSS Calculator** - a React TypeScript application that implements both CVSS v3.1 and v4.0 vulnerability scoring systems for medical device security assessment. The application provides both a guided questionnaire interface for non-technical users and a technical calculator interface for cybersecurity professionals.

## Development Commands

Navigate to the `med-cvss-calculator` directory before running these commands:

```bash
cd med-cvss-calculator

# Development (Vite-powered)
npm start              # Development server (localhost:3000)
npm run dev            # Alternative development command
npm run preview        # Preview production build
npm test               # Run test suite with Vitest
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
npm run build          # Production build (TypeScript compile + Vite build)

# Docker
docker-compose up -d med-cvss-calculator  # Production (port 3000)
docker-compose --profile dev up dev       # Development with hot reload (port 3001)

# Single test execution (Vitest)
npm test -- --run --testNamePattern="specific test name"
npm test -- --run --testPathPattern="filename pattern"

# Deployment
npm run vercel-build   # Vercel-optimized build

# MCP API Testing (for HTTP API mode)
# Test MCP server compatibility - replace YOUR_SERVER_URL with actual URL
npx tsx -e "
import { MCPAPITester } from './src/utils/mcpApiTest';
const tester = new MCPAPITester('YOUR_SERVER_URL');
tester.runAllTests().then(console.log);
"
```

## Architecture Overview

**Build System:**
- **Vite**: Modern build tool replacing Create React App for faster development
- **TypeScript**: Strict mode enabled for type safety
- **Vitest**: Test runner replacing Jest for better integration with Vite
- **ESLint + Prettier**: Code quality and formatting

**Component Architecture:**
- **IntegratedCVSSCalculator**: Main CVSS calculator with support for both v3.1 and v4.0
- **ThreatAnalysis**: AI-powered threat assessment from Japanese descriptions (MCP)
- **MitreCVSSRubric**: MITRE medical device decision tree implementation
- **Authentication Components**: Login, Signup, ProtectedRoute, Navigation with Firebase Auth

**Data Flow:**
1. **Manual Assessment**: User selects CVSS version (v3.1 or v4.0) and metrics through UI components
2. **AI Assessment**: Japanese threat descriptions are analyzed via MCP to extract CVSS metrics
3. Real-time calculation using version-specific algorithms (`cvssCalculator.ts` for v3.1, `cvssV4Calculator.ts` for v4.0)
4. Results display score, severity rating, and vector string for chosen version
5. Optional persistence to localStorage or Firebase Firestore
6. AI results automatically sync to Calculator via localStorage

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
- AI Threat Assessment results automatically saved to localStorage and sync with Calculator
- Firebase Authentication context for user management
- MCP connection state for AI threat analysis
- No external state management library (Redux, Zustand) currently used

## Testing Strategy

- Vitest with React Testing Library (migrated from Jest)
- Coverage thresholds: 70% global, 80% for utils, 60% for data
- Test files in `src/__tests__/` directory
- Key test suites:
  - `cvssCalculator.test.ts`: CVSS v3.1 algorithm validation
  - `cvssV4Calculator.test.ts`: CVSS v4.0 algorithm validation
  - `cvssV4Debug.test.ts`: CVSS v4.0 debug and edge cases
  - `cvssV4Official.test.ts`: CVSS v4.0 official implementation validation
  - `mitre-decision-flow.test.ts`: MITRE rubric testing
  - `mitre-cia-flow.test.ts`: CIA impact assessment

## MCP Integration (Model Context Protocol)

The application integrates with the [med-mcp-threat server](https://github.com/osamusic/med-mcp-threat) for AI-powered threat analysis:

**Architecture:**
- `mcpClient.ts`: MCP client service for communicating with threat extraction server
- `ThreatAnalysis.tsx`: React component providing single threat analysis
- Connection detection via `window.use_mcp_tool` function availability or HTTP API
- Real-time connection status display with fallback handling
- localStorage synchronization between AI results and Calculator

**Key Features:**
- Japanese medical device threat description processing
- Automatic CVSS v3.1 metric extraction from natural language
- Integration with existing CVSS calculator via localStorage sync
- Development mode with mock authentication for local testing

**Environment Variables:**
```bash
# For Claude Desktop mode:
REACT_APP_MCP_THREAT_SERVER=threat-extraction

# For HTTP API mode:
REACT_APP_MCP_SERVER_URL=https://your-mcp-server.vercel.app
```

**Development Mode Authentication:**
- When `REACT_APP_FIREBASE_API_KEY` is not set, the app runs in development mode
- Mock authentication is automatically enabled
- AI Threat Assessment is accessible without Firebase setup
- localStorage-only storage mode

## Important Implementation Details

**Version Compatibility:**
- CVSS v3.1 and v4.0 use different metric sets - automatic reset when switching versions
- MITRE rubric (questionnaire mode) only available for CVSS v3.1
- AI Threat Assessment results automatically populate Calculator metrics

**Authentication Flow:**
- Development mode: Mock authentication when Firebase not configured
- Production mode: Firebase Auth with email/password and Google OAuth
- ThreatAnalysis component is a protected route in production

**Data Persistence:**
- AI Threat Assessment results automatically saved to localStorage
- Calculator automatically loads metrics from localStorage when navigating from AI analysis
- localStorage cleared after loading to prevent stale data
- Firebase Firestore available for cloud storage when configured

**Build System Migration:**
- Migrated from Create React App to Vite for faster development
- TypeScript compilation handled by Vite
- Vitest replaces Jest for testing
- ESLint configuration moved to standalone `.eslintrc.json`
- Custom index.html at project root for Vite

**UI Theme:**
- Soft cyberpunk theme with professional medical device focus
- CSS custom properties for consistent theming
- Inter font for readability
- Component-scoped CSS modules

**Deployment Configuration:**
- Vercel deployment with root directory set to `med-cvss-calculator`
- Vite build output to `./build` directory for compatibility
- Environment variables configured in Vercel dashboard
- Development and production environment files

## Environment Configuration

**Development Mode (.env.development):**
- No Firebase configuration required
- Mock authentication enabled automatically
- localStorage-only storage
- All features available for local development

**Production Deployment:**
- Firebase configuration required for authentication
- Optional MCP server for AI features
- Environment variables in deployment platform

## Firebase Integration (Optional)

For cloud storage and authentication:
1. Create Firebase project with Firestore and Authentication enabled
2. Configure `.env.local` with Firebase credentials
3. Enable desired authentication providers (Email/Password, Google OAuth)
4. See `FIREBASE_SETUP.md` for detailed instructions