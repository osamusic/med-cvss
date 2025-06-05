# Medical Device CVSS Calculator

A comprehensive React TypeScript application that adapts the standard CVSS v3.1 vulnerability scoring system for medical device security assessment. This tool provides specialized interfaces for healthcare professionals to evaluate and track cybersecurity risks in medical devices.

## 🎯 Key Features

### Core Functionality
- **Full CVSS v3.1 Implementation**: Complete Base and Temporal metrics
- **Before/After Risk Assessment**: Evaluate vulnerability reduction after remediation
- **MITRE Decision Flow**: Medical device-specific CVSS assessment guidance
- **Custom Scenarios**: Create, edit, and share vulnerability scenarios
- **Dual Storage Options**: Local storage or Firebase cloud synchronization

### Medical Device Focus
- Pre-built scenarios for common medical devices (infusion pumps, pacemakers, etc.)
- Patient safety and data protection impact assessments
- Healthcare-specific remediation guidance
- Medical device availability considerations
- FDA and healthcare compliance considerations

## 🚀 Quick Start

### Local Development

```bash
# Clone the repository
git clone https://github.com/yourusername/med-cvss.git
cd med-cvss/med-cvss-calculator

# Install dependencies
npm install

# Start development server
npm start
```

The application will be available at `http://localhost:3000`

### Docker Deployment

```bash
# Production deployment
docker-compose up -d med-cvss-calculator

# Development with hot reload
docker-compose --profile dev up dev
```

## 📁 Project Structure

```
med-cvss/
├── med-cvss-calculator/          # Main React application
│   ├── src/
│   │   ├── components/          # React UI components
│   │   ├── data/               # CVSS metrics and medical guidance
│   │   ├── utils/              # Calculation algorithms
│   │   ├── types/              # TypeScript definitions
│   │   ├── hooks/              # Custom React hooks
│   │   ├── services/           # Firebase integration
│   │   └── contexts/           # React contexts
│   ├── public/                 # Static assets
│   └── build/                  # Production build output
├── docker-compose.yml          # Docker configuration
├── Dockerfile                  # Multi-stage Docker build
├── nginx.conf                  # Production web server config
└── CLAUDE.md                   # AI assistant instructions
```

## 🛠️ Development

### Available Commands

```bash
cd med-cvss-calculator

# Development
npm start              # Start dev server (port 3000)
npm test               # Run tests in watch mode
npm run test:coverage  # Generate coverage report
npm run test:mitre     # Run MITRE-specific tests

# Code Quality
npm run lint           # ESLint analysis
npm run lint:fix       # Auto-fix linting issues
npm run format         # Prettier formatting
npm run type-check     # TypeScript validation
npm run quality        # Run all quality checks

# Production
npm run build          # Create production build
```

### Technology Stack

- **Frontend**: React 19.1.0 with TypeScript
- **Routing**: React Router DOM v7
- **Styling**: Component-scoped CSS with gradients
- **Storage**: localStorage or Firebase Firestore
- **Authentication**: Firebase Auth (optional)
- **Testing**: Jest + React Testing Library
- **Deployment**: Docker with nginx

## 🔒 Security Features

- No storage of actual patient data or PHI
- Optional Firebase Authentication for user isolation
- Secure HTTPS enforcement in production
- Input validation for all CVSS metrics
- Export/import functionality with data sanitization

## 📊 CVSS Implementation

### Supported Metrics

**Base Metrics**
- Attack Vector (AV)
- Attack Complexity (AC)
- Privileges Required (PR)
- User Interaction (UI)
- Scope (S)
- Confidentiality Impact (C)
- Integrity Impact (I)
- Availability Impact (A)

**Temporal Metrics**
- Exploit Code Maturity (E)
- Remediation Level (RL)
- Report Confidence (RC)

### Calculation Algorithm

The application implements the official CVSS v3.1 scoring algorithm:
1. Calculate Impact Sub Score (ISS)
2. Calculate Impact Score
3. Calculate Exploitability Score
4. Combine for Base Score (0-10)
5. Apply Temporal modifiers

## 🏥 Medical Device Scenarios

Pre-configured scenarios include:
- Network-connected infusion pumps
- Bluetooth-enabled cardiac devices
- Hospital information systems
- Medical imaging equipment
- Remote patient monitoring devices
- Laboratory diagnostic systems

## 🔧 Configuration

### Firebase Setup (Optional)

For cloud storage and authentication:

1. Create a Firebase project
2. Enable Firestore and Authentication
3. Create `.env.local` with your configuration:
   ```env
   REACT_APP_FIREBASE_API_KEY=your-api-key
   REACT_APP_FIREBASE_AUTH_DOMAIN=your-auth-domain
   REACT_APP_FIREBASE_PROJECT_ID=your-project-id
   REACT_APP_FIREBASE_STORAGE_BUCKET=your-storage-bucket
   REACT_APP_FIREBASE_MESSAGING_SENDER_ID=your-sender-id
   REACT_APP_FIREBASE_APP_ID=your-app-id
   ```
4. See [med-cvss-calculator/FIREBASE_SETUP.md](./med-cvss-calculator/FIREBASE_SETUP.md) for detailed instructions

### Storage Options

```typescript
// Local storage (default)
const scenarios = useCustomScenarios('localStorage');

// Firebase cloud storage
const scenarios = useCustomScenarios('firebase', userId);
```

## 🧪 Testing

The project includes comprehensive test coverage:

```bash
# Run all tests
npm test

# Coverage report
npm run test:coverage

# Specific test suites
npm run test:mitre
```

Test coverage targets:
- Global: 70%
- Utils: 80%
- Data: 60%

## 📦 Deployment

### Firebase Hosting

```bash
cd med-cvss-calculator
npm run build
firebase deploy
```

### Docker Production

```bash
docker build -t med-cvss-calculator .
docker run -p 80:80 med-cvss-calculator
```

### Static Hosting

The built application can be deployed to any static hosting service:
- Vercel
- Netlify
- AWS S3 + CloudFront
- GitHub Pages

## 📚 Documentation

- [CLAUDE.md](./CLAUDE.md) - AI assistant development guide
- [Firebase Setup](./med-cvss-calculator/FIREBASE_SETUP.md) - Cloud integration guide
- [Test Summary](./med-cvss-calculator/TEST_SUMMARY.md) - Testing documentation
- [Component README](./med-cvss-calculator/README.md) - React app details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -m 'Add your feature'`)
4. Push to branch (`git push origin feature/your-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow existing code style and patterns
- Add tests for new functionality
- Update documentation as needed
- Run `npm run quality` before submitting PR
- Ensure all tests pass in CI/CD

## 📄 License

This project is designed for educational and professional use in healthcare cybersecurity assessment.

## 🆘 Support

- Create an issue for bug reports or feature requests
- Check existing documentation for common questions
- Review test files for implementation examples

---

Built with ❤️ for the healthcare cybersecurity community