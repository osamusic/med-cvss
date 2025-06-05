# Pull Request

## 📋 Description
<!-- Provide a brief description of the changes in this PR -->

## 🔧 Type of Change
<!-- Mark the relevant option with an "x" -->
- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🧪 Test improvements
- [ ] 🔧 Refactoring (no functional changes)
- [ ] 🎨 UI/UX improvements
- [ ] 🏥 Medical device CVSS logic changes
- [ ] 📊 MITRE rubric updates

## 🏥 Medical Device Impact
<!-- If this PR affects medical device CVSS calculation logic -->
- [ ] Changes affect CVSS base score calculation
- [ ] Changes affect medical device guidance
- [ ] Changes affect MITRE rubric decision flows
- [ ] Changes affect patient data handling logic
- [ ] No impact on medical device functionality

## 🧪 Testing
<!-- Describe the tests you ran to verify your changes -->
- [ ] Unit tests pass (`npm test`)
- [ ] MITRE decision flow tests pass (`npm test -- --testPathPattern="mitre.*flow"`)
- [ ] Build succeeds (`npm run build`)
- [ ] Manual testing completed
- [ ] Medical device scenarios tested

### Test Coverage
<!-- If you added new functionality, describe test coverage -->
- [ ] Added unit tests for new functionality
- [ ] Updated existing tests
- [ ] Added medical device test scenarios
- [ ] No tests needed (explain why)

## 📸 Screenshots
<!-- If UI changes, add screenshots -->
<!-- For CVSS calculator changes, show before/after of score calculations -->

## 🔍 Code Quality Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Code is commented, particularly in hard-to-understand areas
- [ ] No console.log statements left in production code
- [ ] TypeScript types are properly defined
- [ ] Medical device guidance text is accurate
- [ ] HIPAA considerations addressed (if applicable)

## 🔒 Security Considerations
<!-- Mark if any apply -->
- [ ] Changes handle patient data (PHI/PII)
- [ ] New dependencies added (reviewed for vulnerabilities)
- [ ] Authentication/authorization changes
- [ ] Input validation added/updated
- [ ] No security concerns

## 📚 Documentation
- [ ] Updated README if needed
- [ ] Updated API documentation
- [ ] Updated medical device guidance
- [ ] Added inline code comments
- [ ] Updated CLAUDE.md if architectural changes

## 🔗 Related Issues
<!-- Link any related issues -->
Closes #
Relates to #

## 📋 Deployment Notes
<!-- Any special deployment considerations -->
- [ ] Database migrations needed
- [ ] Environment variables changed
- [ ] Breaking changes require communication
- [ ] No special deployment steps needed

## 🧑‍⚕️ Medical Professional Review
<!-- For medical device logic changes -->
- [ ] Medical professional review recommended
- [ ] Clinical workflow impact assessed
- [ ] Patient safety considerations reviewed
- [ ] Regulatory compliance maintained

## ✅ Reviewer Checklist
<!-- For reviewers -->
- [ ] Code changes reviewed thoroughly
- [ ] Test coverage is adequate
- [ ] Medical device logic is sound
- [ ] Security considerations addressed
- [ ] Documentation is sufficient
- [ ] Performance impact considered