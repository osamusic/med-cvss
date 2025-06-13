# Medical Device CVSS Calculator

A React TypeScript application that implements both CVSS v3.1 and v4.0 vulnerability scoring systems for medical device security assessment. The application provides both a guided questionnaire interface for non-technical users and a technical calculator interface for cybersecurity professionals.

## ✨ Features

- **CVSS v3.1 & v4.0 Calculator**: Full implementation of both CVSS specifications
- **AI Threat Assessment**: Automated CVSS scoring from Japanese threat descriptions using MCP
- **Before/After Comparison**: Evaluate risk reduction after implementing remediation measures
- **Medical Device Scenarios**: Pre-built scenarios for healthcare environments
- **Custom Scenarios**: Create, edit, and manage your own remediation scenarios
- **Data Persistence**: Choose between localStorage or Firebase cloud storage
- **Export/Import**: Share scenarios between teams and environments
- **User Authentication**: Secure user-specific data with Firebase Auth

## 🏥 Medical Device Focus

Designed specifically for healthcare environments with:
- Patient data protection scenarios
- Medical device availability considerations
- Healthcare integrity impact assessments
- Device-specific vulnerability examples (infusion pumps, Bluetooth devices, etc.)

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ and npm
- Firebase project (optional, for cloud storage and authentication)
- Claude Desktop with MCP support (optional, for AI threat assessment)

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. **For Local Storage Only** (Skip Firebase setup):
   ```bash
   npm start
   ```

4. **For Full Features (Firebase + MCP)**:
   - Follow the [Firebase Setup Guide](./FIREBASE_SETUP.md)
   - Copy `.env.example` to `.env.local`
   - Add your Firebase configuration
   - Set up [med-mcp-threat server](https://github.com/osamusic/med-mcp-threat) in Claude Desktop
   - Start the application:
     ```bash
     npm start
     ```

This project was bootstrapped with [Create React App](https://github.com/facebook/create-react-app).

## Available Scripts

In the project directory, you can run:

### `npm start`

Runs the app in the development mode.\
Open [http://localhost:3000](http://localhost:3000) to view it in the browser.

The page will reload if you make edits.\
You will also see any lint errors in the console.

### `npm test`

Launches the test runner in the interactive watch mode.\
See the section about [running tests](https://facebook.github.io/create-react-app/docs/running-tests) for more information.

### `npm run build`

Builds the app for production to the `build` folder.\
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.\
Your app is ready to be deployed!

See the section about [deployment](https://facebook.github.io/create-react-app/docs/deployment) for more information.

### `npm run eject`

**Note: this is a one-way operation. Once you `eject`, you can’t go back!**

If you aren’t satisfied with the build tool and configuration choices, you can `eject` at any time. This command will remove the single build dependency from your project.

Instead, it will copy all the configuration files and the transitive dependencies (webpack, Babel, ESLint, etc) right into your project so you have full control over them. All of the commands except `eject` will still work, but they will point to the copied scripts so you can tweak them. At this point you’re on your own.

You don’t have to ever use `eject`. The curated feature set is suitable for small and middle deployments, and you shouldn’t feel obligated to use this feature. However we understand that this tool wouldn’t be useful if you couldn’t customize it when you are ready for it.

## Learn More

You can learn more in the [Create React App documentation](https://facebook.github.io/create-react-app/docs/getting-started).

To learn React, check out the [React documentation](https://reactjs.org/).

## 🏗️ Architecture

### Component Structure
- **IntegratedCVSSCalculator**: Technical CVSS metric selection interface with real-time calculation
- **ThreatAnalysis**: AI-powered threat assessment from Japanese descriptions (MCP)
- **CVSSComparison**: Before/after evaluation with custom scenario management
- **ScenarioEditor**: Modal interface for creating and editing scenarios
- **Authentication**: Firebase Auth integration for secure user sessions

### Data Flow
1. **Manual Assessment**: Questionnaire collects user responses and maps to CVSS metrics
2. **AI Assessment**: Japanese threat descriptions are analyzed via MCP to extract CVSS metrics
3. Navigation state passes selected values to calculator
4. Calculator performs real-time CVSS v3.1/v4.0 calculations
5. Results display score, severity rating, and vector string
6. Custom scenarios are stored locally or in Firebase Firestore

### Key Technologies
- **React 19** with TypeScript
- **Firebase**: Authentication and Firestore database
- **MCP (Model Context Protocol)**: AI threat analysis integration
- **CVSS v3.1 & v4.0**: Full specification implementation
- **Component-scoped CSS**: Modular styling approach

## 🔧 Configuration

### Storage Options

**Local Storage** (Default):
```typescript
const scenarioManager = useCustomScenarios('localStorage');
```

**Firebase Cloud Storage**:
```typescript
const scenarioManager = useCustomScenarios('firebase', user?.uid);
```

### Environment Variables

Create a `.env.local` file by copying `.env.example` and configure the following variables:

#### Firebase Configuration (Required for authentication and cloud storage)
```bash
# Firebase project settings from Firebase Console > Project Settings > General
REACT_APP_FIREBASE_API_KEY=your_api_key_here
REACT_APP_FIREBASE_AUTH_DOMAIN=your_project_id.firebaseapp.com
REACT_APP_FIREBASE_PROJECT_ID=your_project_id
REACT_APP_FIREBASE_STORAGE_BUCKET=your_project_id.appspot.com
REACT_APP_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
REACT_APP_FIREBASE_APP_ID=your_app_id

# Optional: Development settings
REACT_APP_USE_FIREBASE_EMULATOR=false
REACT_APP_FIREBASE_DEBUG=false
```

#### Storage Configuration
```bash
# Choose storage backend: 'localStorage' or 'firebase'
REACT_APP_DEFAULT_STORAGE_TYPE=localStorage
```

#### MCP Threat Analysis Configuration
```bash
# Enable MCP threat extraction features
REACT_APP_MCP_ENABLED=true
# MCP server name for threat extraction
REACT_APP_MCP_THREAT_SERVER=threat-extraction
```

**Note**: MCP features require Claude Desktop with the [med-mcp-threat server](https://github.com/osamusic/med-mcp-threat) configured.

## 🤖 AI Threat Assessment (MCP)

The application integrates with the [med-mcp-threat server](https://github.com/osamusic/med-mcp-threat) to provide AI-powered CVSS scoring from Japanese threat descriptions.

### Features
- **Japanese Language Support**: Optimized for Japanese medical device threat descriptions
- **Automatic CVSS Extraction**: AI analysis extracts CVSS v3.1 metrics from threat text
- **Batch Processing**: Analyze multiple threats simultaneously
- **Medical Device Focus**: Specialized for healthcare device vulnerabilities

### Requirements
1. **Claude Desktop**: Install and configure Claude Desktop
2. **MCP Server**: Set up the [med-mcp-threat server](https://github.com/osamusic/med-mcp-threat)
3. **Authentication**: Sign in to access the AI Threat Assessment feature

### Usage
1. Navigate to "AI Threat Assessment (Japanese only)" after signing in
2. Enter Japanese threat descriptions (samples provided)
3. AI extracts CVSS metrics and calculates scores automatically
4. Review results and navigate to detailed CVSS calculator if needed

## 📊 CVSS Implementation

The application implements both CVSS v3.1 and v4.0 specifications:

**CVSS v3.1 Features:**
- **Base Metrics**: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, C/I/A Impact
- **Temporal Metrics**: Exploit Code Maturity, Remediation Level, Report Confidence
- **Environmental Metrics**: Modified Base metrics and C/I/A Requirements

**CVSS v4.0 Features:**
- **Base Metrics**: Attack Vector, Attack Complexity, Attack Requirements, Privileges Required, User Interaction, Vulnerable/Subsequent System Impact
- **Threat Metrics**: Exploit Maturity
- **Environmental Metrics**: Modified metrics and C/I/A Requirements
- **Supplemental Metrics**: Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort, Provider Urgency

## 🧪 Testing

Run the test suite:
```bash
npm test
```

The project includes comprehensive tests for:
- CVSS calculation algorithms
- Medical device scenario validation
- Before/after comparison logic
- Data import/export functionality

## 🚀 Deployment

### Firebase Hosting
```bash
npm run build
firebase deploy
```

### Other Platforms
The built application can be deployed to any static hosting platform (Vercel, Netlify, etc.).

## 🔒 Security

- Firebase Authentication for user management
- Firestore security rules for data isolation
- No sensitive medical data stored (only CVSS metrics)
- HTTPS enforcement in production

## 📚 Documentation

- [Firebase Setup Guide](./FIREBASE_SETUP.md) - Complete Firebase configuration
- [TEST_SUMMARY.md](./TEST_SUMMARY.md) - Testing overview
- Component documentation in source files

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is intended for educational and professional use in healthcare cybersecurity.

### Third-Party Components

This project incorporates code from the RedHat CVSS v4.0 Calculator:
- **Source**: [RedHat CVSS v4.0 Calculator](https://github.com/RedHatProductSecurity/cvss-v4-calculator)
- **Copyright**: FIRST.ORG, Inc., Red Hat, and contributors
- **License**: BSD-2-Clause
- **Components**: CVSS v4.0 scoring algorithm and lookup tables in `src/utils/cvssV4Official.ts`

The original BSD-2-Clause license text is included in the source file header.
