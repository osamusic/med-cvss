export interface MitreQuestion {
  id: string;
  text: string;
  category: string;
  type: 'decision' | 'classification' | 'assessment';
  options: {
    value: string;
    label: string;
    nextQuestion?: string;
    cvssValue?: string;
  }[];
  description?: string;
  guidance?: string;
}

export interface MitreRubricAnswers {
  [questionId: string]: string;
}

// Medical Device CVSS Rubric Implementation - Updated with Extended Questions
export const mitreRubricQuestions: MitreQuestion[] = [
  
  // ATTACK VECTOR - Extended Medical Device Assessment
  {
    id: "XAVN",
    text: "Q1 (XAVN). Can the attacker utilize some type of network or communication protocol to exploit this vulnerability?",
    category: "Attack Vector",
    type: "decision",
    description: "Network/communication protocol usage determines base attack vector",
    guidance: "Consider any network protocols including IP, TCP/UDP, wireless, or communication interfaces",
    options: [
      { 
        value: "yes", 
        label: "Yes - Can utilize network/communication protocol",
        nextQuestion: "XAVT"
      },
      { 
        value: "no", 
        label: "No - Cannot use network/communication protocol",
        nextQuestion: "XAVP"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain about network/communication protocol usage",
        cvssValue: "N"
      }
    ]
  },

  {
    id: "XAVT",
    text: "Q2 (XAVT). Does the network use OSI layer 3 or 4 protocols, e.g. IP, TCP/IP, or UDP?",
    category: "Attack Vector",
    type: "decision",
    description: "OSI layer 3/4 protocols indicate network-level accessibility",
    options: [
      { 
        value: "yes", 
        label: "Yes - Uses OSI layer 3/4 protocols (IP, TCP/IP, UDP)",
        cvssValue: "N"
      },
      { 
        value: "no", 
        label: "No - Does not use OSI layer 3/4 protocols",
        nextQuestion: "XAVW"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain about OSI layer protocols",
        cvssValue: "N"
      }
    ]
  },

  {
    id: "XAVW",
    text: "Q3 (XAVW). Is the communication over a wireless channel?",
    category: "Attack Vector",
    type: "decision",
    description: "Wireless communication affects accessibility",
    options: [
      { 
        value: "yes", 
        label: "Yes - Communication is over wireless channel",
        nextQuestion: "XAVR",
        cvssValue: "A"
      },
      { 
        value: "no", 
        label: "No - Communication is not wireless",
        cvssValue: "L"
      }
    ]
  },

  {
    id: "XAVR",
    text: "Q4 (XAVR). Is the range approximately 10 feet or less?",
    category: "Attack Vector",
    type: "decision",
    description: "Short-range wireless requires physical proximity",
    options: [
      { 
        value: "yes", 
        label: "Yes - Range is 10 feet or less",
        cvssValue: "L"
      },
      { 
        value: "no", 
        label: "No - Range is greater than 10 feet",
        cvssValue: "A"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain about range",
        cvssValue: "A"
      }
    ]
  },

  {
    id: "XAVP",
    text: "Q5 (XAVP). Must the attacker have physical contact with the device?",
    category: "Attack Vector",
    type: "decision",
    description: "Physical contact requirement determines access level",
    options: [
      { 
        value: "yes", 
        label: "Yes - Physical contact required",
        nextQuestion: "XAVPA",
        cvssValue: "P"
      },
      { 
        value: "no", 
        label: "No - Physical contact not required",
        cvssValue: "L"
      }
    ]
  },

  {
    id: "XAVPA",
    text: "Q5.1 (XAVPA). Is the device accessed through a 'human-user interface,' i.e. a user interface intended for manual operation by device users?",
    category: "Attack Vector",
    type: "decision",
    description: "Human-user interface accessibility",
    options: [
      { 
        value: "yes", 
        label: "Yes - Accessed through human-user interface",
        cvssValue: "P"
      },
      { 
        value: "no", 
        label: "No - Not accessed through human-user interface",
        cvssValue: "P"
      }
    ]
  },

  // ATTACK COMPLEXITY - Extended Medical Device Assessment
  {
    id: "XACL",
    text: "Q1 (XACL). Can the attacker attempt to exploit the vulnerability at will, i.e., without requiring any special circumstances, configurations, or use of other vulnerabilities or attacks before attacking this vulnerability?",
    category: "Attack Complexity",
    type: "decision",
    description: "Determines if exploitation requires special conditions or can be done at will",
    guidance: "Consider if attacker needs specific timing, device states, or preparation",
    options: [
      { 
        value: "yes", 
        label: "Yes - Can exploit at will without special circumstances",
        cvssValue: "L"
      },
      { 
        value: "no", 
        label: "No - Requires special circumstances, configurations, or other vulnerabilities",
        cvssValue: "H"
      }
    ]
  },

  // PRIVILEGES REQUIRED - Extended Medical Device Assessment
  {
    id: "XPRL",
    text: "Q1 (XPRL). Does the device/component use an authorization model that supports login for multiple different users or roles with different privilege levels?",
    category: "Privileges Required", 
    type: "decision",
    description: "Determines if device has multi-user authorization model",
    guidance: "Consider if device supports different user roles with varying access levels",
    options: [
      { 
        value: "yes", 
        label: "Yes - Device uses multi-user authorization model",
        nextQuestion: "XPRZ",
        cvssValue: "L"
      },
      { 
        value: "no", 
        label: "No - Device does not use multi-user authorization",
        cvssValue: "N"
      }
    ]
  },

  {
    id: "XPRZ",
    text: "Q2 (XPRZ). Before attempting to exploit the vulnerability, must the attacker be authorized to the affected component?",
    category: "Privileges Required",
    type: "decision",
    description: "Determines if authorization is required before exploitation",
    options: [
      { 
        value: "yes", 
        label: "Yes - Attacker must be authorized to affected component",
        nextQuestion: "XPRS",
        cvssValue: "L"
      },
      { 
        value: "no", 
        label: "No - No authorization required",
        cvssValue: "N"
      }
    ]
  },

  {
    id: "XPRS",
    text: "Q3 (XPRS). Must the attacker have administrator, maintainer, or other system-level privileges to attempt to exploit the vulnerability?",
    category: "Privileges Required",
    type: "decision",
    description: "Determines if high-level privileges are required",
    options: [
      { 
        value: "yes", 
        label: "Yes - Requires administrator/maintainer/system-level privileges",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Does not require high-level privileges",
        cvssValue: "L"
      }
    ]
  },

  // USER INTERACTION - Extended Medical Device Assessment
  {
    id: "XUI", 
    text: "Q1 (XUI). To successfully exploit the vulnerability, must the attacker depend on another user or victim to perform an action or otherwise interact with the system?",
    category: "User Interaction",
    type: "decision",
    description: "Determines if user interaction is required for successful exploitation",
    guidance: "Consider if exploitation requires user actions like clicking, opening files, or system interactions",
    options: [
      { 
        value: "no", 
        label: "No - No user interaction required",
        cvssValue: "N"
      },
      { 
        value: "yes", 
        label: "Yes - Requires user/victim to perform action or interact with system",
        cvssValue: "R"
      }
    ]
  },

  // SCOPE - Extended Medical Device Assessment
  {
    id: "XS",
    text: "Q1 (XS). Can the attacker affect a component whose authority ('authorization scope') is different than that of the vulnerable component?",
    category: "Scope",
    type: "decision", 
    description: "Determines if impact extends beyond vulnerable component's authorization scope",
    guidance: "Consider if exploitation can affect other components with different authorization boundaries",
    options: [
      { 
        value: "no", 
        label: "No - Impact limited to vulnerable component's authorization scope",
        cvssValue: "U"
      },
      { 
        value: "yes", 
        label: "Yes - Can affect components with different authorization scope",
        cvssValue: "C"
      }
    ]
  },

  // CONFIDENTIALITY IMPACT - PHI/PII Data
  {
    id: "XCP",
    text: "Q1.C (XCP): Can PHI/PII data be read?",
    category: "Confidentiality Impact",
    type: "decision",
    description: "Patient Health Information / Personally Identifiable Information exposure",
    guidance: "Consider if attacker can access patient personal information, medical records, or identifying data",
    options: [
      { 
        value: "yes", 
        label: "Yes - PHI/PII data can be read",
        nextQuestion: "XCPM",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - PHI/PII data cannot be read",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if PHI/PII data can be read",
        cvssValue: "H"
      }
    ]
  },

  {
    id: "XCPM",
    text: "Q1.1.C (XCPM): Can the exposed data cover a large number of patients, e.g. 500 or more, which may force regulatory action or data breach notification (e.g. HIPAA, GDPR)?",
    category: "Confidentiality Impact",
    type: "decision",
    description: "Scale of PHI/PII exposure for regulatory impact assessment",
    options: [
      { 
        value: "yes", 
        label: "Yes - Large scale exposure (500+ patients, regulatory action required)",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Limited exposure (less than 500 patients)",
        cvssValue: "L"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain about scale of exposure",
        cvssValue: "H"
      }
    ]
  },

  // CONFIDENTIALITY IMPACT - Diagnosis/Monitoring Data
  {
    id: "XCD",
    text: "Q2.C (XCD): Can diagnosis or monitoring data/functionality be read/exposed?",
    category: "Confidentiality Impact",
    type: "decision",
    description: "Diagnostic and monitoring system data exposure",
    options: [
      { 
        value: "yes", 
        label: "Yes - Diagnosis/monitoring data can be read/exposed",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Diagnosis/monitoring data cannot be read/exposed",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if diagnosis/monitoring data can be read/exposed",
        cvssValue: "H"
      }
    ]
  },

  // CONFIDENTIALITY IMPACT - Therapy Delivery Data
  {
    id: "XCT",
    text: "Q3.C (XCT): Can therapy delivery data/functionality be read/exposed?",
    category: "Confidentiality Impact",
    type: "decision",
    description: "Therapy delivery system data exposure",
    options: [
      { 
        value: "yes", 
        label: "Yes - Therapy delivery data can be read/exposed",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Therapy delivery data cannot be read/exposed",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if therapy delivery data can be read/exposed",
        cvssValue: "H"
      }
    ]
  },

  // CONFIDENTIALITY IMPACT - Clinical Workflow Data
  {
    id: "XCW",
    text: "Q4.C (XCW): Can clinical workflow data/functionality be read/exposed?",
    category: "Confidentiality Impact",
    type: "decision",
    description: "Clinical workflow system data exposure",
    options: [
      { 
        value: "yes", 
        label: "Yes - Clinical workflow data can be read/exposed",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Clinical workflow data cannot be read/exposed",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if clinical workflow data can be read/exposed",
        cvssValue: "H"
      }
    ]
  },

  // CONFIDENTIALITY IMPACT - Private System Data
  {
    id: "XCS",
    text: "Q5.C (XCS): Can private system or system-user data (e.g. passwords, private keys) be read/exposed?",
    category: "Confidentiality Impact",
    type: "decision",
    description: "Private system data and credentials exposure",
    options: [
      { 
        value: "yes", 
        label: "Yes - Private system/user data can be read/exposed",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Private system/user data cannot be read/exposed",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if private system/user data can be read/exposed",
        cvssValue: "H"
      }
    ]
  },

  // CONFIDENTIALITY IMPACT - Other Critical Data
  {
    id: "XCO",
    text: "Q6.C (XCO): Can any other kind of critical, sensitive data/functionality be read/exposed?",
    category: "Confidentiality Impact",
    type: "decision",
    description: "Other critical or sensitive data exposure",
    options: [
      { 
        value: "yes", 
        label: "Yes - Other critical/sensitive data can be read/exposed",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Other critical/sensitive data cannot be read/exposed",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if other critical/sensitive data can be read/exposed",
        cvssValue: "H"
      }
    ]
  },

  // INTEGRITY IMPACT - PHI/PII Data
  {
    id: "XIP",
    text: "Q1.I (XIP): Can PHI/PII data be modified/deleted?",
    category: "Integrity Impact",
    type: "decision",
    description: "Patient Health Information / Personally Identifiable Information modification/deletion",
    guidance: "Consider if attacker can alter or delete patient personal information or medical records",
    options: [
      { 
        value: "yes", 
        label: "Yes - PHI/PII data can be modified/deleted",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - PHI/PII data cannot be modified/deleted",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if PHI/PII data can be modified/deleted",
        cvssValue: "H"
      }
    ]
  },

  // INTEGRITY IMPACT - Diagnosis/Monitoring Data
  {
    id: "XID",
    text: "Q2.I (XID): Can diagnosis or monitoring data/functionality be modified/deleted?",
    category: "Integrity Impact",
    type: "decision",
    description: "Diagnostic and monitoring system data modification/deletion",
    options: [
      { 
        value: "yes", 
        label: "Yes - Diagnosis/monitoring data can be modified/deleted",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Diagnosis/monitoring data cannot be modified/deleted",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if diagnosis/monitoring data can be modified/deleted",
        cvssValue: "H"
      }
    ]
  },

  // INTEGRITY IMPACT - Therapy Delivery Data
  {
    id: "XIT",
    text: "Q3.I (XIT): Can therapy delivery data/functionality be modified/deleted?",
    category: "Integrity Impact",
    type: "decision",
    description: "Therapy delivery system data modification/deletion",
    options: [
      { 
        value: "yes", 
        label: "Yes - Therapy delivery data can be modified/deleted",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Therapy delivery data cannot be modified/deleted",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if therapy delivery data can be modified/deleted",
        cvssValue: "H"
      }
    ]
  },

  // INTEGRITY IMPACT - Clinical Workflow Data
  {
    id: "XIW",
    text: "Q4.I (XIW): Can clinical workflow data/functionality be modified/deleted?",
    category: "Integrity Impact",
    type: "decision",
    description: "Clinical workflow system data modification/deletion",
    options: [
      { 
        value: "yes", 
        label: "Yes - Clinical workflow data can be modified/deleted",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Clinical workflow data cannot be modified/deleted",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if clinical workflow data can be modified/deleted",
        cvssValue: "H"
      }
    ]
  },

  // INTEGRITY IMPACT - Private System Data
  {
    id: "XIS",
    text: "Q5.I (XIS): Can private system or system-user data (e.g. passwords, private keys) be modified/deleted?",
    category: "Integrity Impact",
    type: "decision",
    description: "Private system data and credentials modification/deletion",
    options: [
      { 
        value: "yes", 
        label: "Yes - Private system/user data can be modified/deleted",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Private system/user data cannot be modified/deleted",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if private system/user data can be modified/deleted",
        cvssValue: "H"
      }
    ]
  },

  // INTEGRITY IMPACT - Other Critical Data
  {
    id: "XIO",
    text: "Q6.I (XIO): Can any other kind of critical, sensitive data/functionality be modified/deleted?",
    category: "Integrity Impact",
    type: "decision",
    description: "Other critical or sensitive data modification/deletion",
    options: [
      { 
        value: "yes", 
        label: "Yes - Other critical/sensitive data can be modified/deleted",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Other critical/sensitive data cannot be modified/deleted",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if other critical/sensitive data can be modified/deleted",
        cvssValue: "H"
      }
    ]
  },

  // AVAILABILITY IMPACT - PHI/PII Data
  {
    id: "XAP",
    text: "Q1.A (XAP): Can PHI/PII data be rendered inaccessible?",
    category: "Availability Impact", 
    type: "decision",
    description: "Patient Health Information / Personally Identifiable Information availability",
    guidance: "Consider if attacker can make patient personal information or medical records unavailable",
    options: [
      { 
        value: "yes", 
        label: "Yes - PHI/PII data can be rendered inaccessible",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - PHI/PII data cannot be rendered inaccessible",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if PHI/PII data can be rendered inaccessible",
        cvssValue: "H"
      }
    ]
  },

  // AVAILABILITY IMPACT - Diagnosis/Monitoring Data
  {
    id: "XAD",
    text: "Q2.A (XAD): Can diagnosis or monitoring data/functionality be rendered inaccessible?",
    category: "Availability Impact",
    type: "decision",
    description: "Diagnostic and monitoring system availability",
    options: [
      { 
        value: "yes", 
        label: "Yes - Diagnosis/monitoring data can be rendered inaccessible",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Diagnosis/monitoring data cannot be rendered inaccessible",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if diagnosis/monitoring data can be rendered inaccessible",
        cvssValue: "H"
      }
    ]
  },

  // AVAILABILITY IMPACT - Therapy Delivery Data
  {
    id: "XAT",
    text: "Q3.A (XAT): Can therapy delivery data/functionality be rendered inaccessible?",
    category: "Availability Impact",
    type: "decision",
    description: "Therapy delivery system availability",
    options: [
      { 
        value: "yes", 
        label: "Yes - Therapy delivery data can be rendered inaccessible",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Therapy delivery data cannot be rendered inaccessible",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if therapy delivery data can be rendered inaccessible",
        cvssValue: "H"
      }
    ]
  },

  // AVAILABILITY IMPACT - Clinical Workflow Data
  {
    id: "XAW",
    text: "Q4.A (XAW): Can clinical workflow data/functionality be rendered inaccessible?",
    category: "Availability Impact",
    type: "decision",
    description: "Clinical workflow system availability",
    options: [
      { 
        value: "yes", 
        label: "Yes - Clinical workflow data can be rendered inaccessible",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Clinical workflow data cannot be rendered inaccessible",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if clinical workflow data can be rendered inaccessible",
        cvssValue: "H"
      }
    ]
  },

  // AVAILABILITY IMPACT - Private System Data
  {
    id: "XAS",
    text: "Q5.A (XAS): Can private system or system-user data (e.g. passwords, private keys) be rendered inaccessible?",
    category: "Availability Impact",
    type: "decision",
    description: "Private system data and credentials availability",
    options: [
      { 
        value: "yes", 
        label: "Yes - Private system/user data can be rendered inaccessible",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Private system/user data cannot be rendered inaccessible",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if private system/user data can be rendered inaccessible",
        cvssValue: "H"
      }
    ]
  },

  // AVAILABILITY IMPACT - Other Critical Data
  {
    id: "XAO",
    text: "Q6.A (XAO): Can any other kind of critical, sensitive data/functionality be rendered inaccessible?",
    category: "Availability Impact",
    type: "decision",
    description: "Other critical or sensitive data availability",
    options: [
      { 
        value: "yes", 
        label: "Yes - Other critical/sensitive data can be rendered inaccessible",
        cvssValue: "H"
      },
      { 
        value: "no", 
        label: "No - Other critical/sensitive data cannot be rendered inaccessible",
        cvssValue: "N"
      },
      { 
        value: "unknown", 
        label: "Unknown - Uncertain if other critical/sensitive data can be rendered inaccessible",
        cvssValue: "H"
      }
    ]
  }
];

export const calculateMitreVector = (answers: MitreRubricAnswers): { [key: string]: string } => {
  const vector: { [key: string]: string } = {};
  
  // Attack Vector - Extended Medical Device Logic based on MITRE decision tree
  if (answers.XAVN === 'yes') {
    // Q1 = Yes: Can use network/communication protocol → Q2
    if (answers.XAVT === 'yes') {
      // Q2 = Yes: Uses OSI layer 3/4 protocols → AV = Network (N)
      vector.AV = 'N';
    } else if (answers.XAVT === 'no') {
      // Q2 = No: Does not use OSI layer 3/4 protocols → Q3
      if (answers.XAVW === 'yes') {
        // Q3 = Yes: Wireless communication → Q4
        if (answers.XAVR === 'yes') {
          // Q4 = Yes: Range ≤10ft → AV = Local (L)
          vector.AV = 'L';
        } else {
          // Q4 = No/Unknown: Range >10ft → AV = Adjacent (A)
          vector.AV = 'A';
        }
      } else {
        // Q3 = No/Unknown: Not wireless → AV = Adjacent (A)
        vector.AV = 'A';
      }
    } else {
      // Q2 = Unknown → AV = Network (N)
      vector.AV = 'N';
    }
  } else if (answers.XAVN === 'no') {
    // Q1 = No: Cannot use network/communication protocol → Q5
    if (answers.XAVP === 'yes') {
      // Q5 = Yes: Physical contact required → AV = Physical (P)
      vector.AV = 'P';
    } else {
      // Q5 = No/Unknown: No physical contact required → AV = Local (L)
      vector.AV = 'L';
    }
  } else {
    // Q1 = Unknown → AV = Network (N)
    vector.AV = 'N';
  }
  
  // Attack Complexity
  if (answers.XACL) {
    vector.AC = answers.XACL === 'yes' ? 'L' : 'H';
  }
  
  // Privileges Required
  if (answers.XPRL) {
    if (answers.XPRL === 'no') {
      // No multi-user authorization
      vector.PR = 'N';
    } else {
      // Has multi-user authorization
      if (answers.XPRZ === 'no') {
        // No authorization required
        vector.PR = 'N';
      } else {
        // Authorization required
        vector.PR = answers.XPRS === 'yes' ? 'H' : 'L';
      }
    }
  }
  
  // User Interaction
  if (answers.XUI) {
    vector.UI = answers.XUI === 'no' ? 'N' : 'R';
  }
  
  // Scope
  if (answers.XS) {
    vector.S = answers.XS === 'no' ? 'U' : 'C';
  }
  
  // Confidentiality Impact - Extended Logic
  const confidentialityImpacts: { [key: string]: 'H' | 'L' | 'N' | undefined } = {};
  
  // Q1.C (XCP) - PHI/PII data
  if (answers.XCP) {
    if (answers.XCP === 'yes') {
      // Check scale with Q1.1.C (XCPM)
      if (answers.XCPM) {
        confidentialityImpacts.XCP = (answers.XCPM === 'yes' || answers.XCPM === 'unknown') ? 'H' : 'L';
      } else {
        confidentialityImpacts.XCP = 'H'; // Default to High if scale not answered
      }
    } else if (answers.XCP === 'no') {
      confidentialityImpacts.XCP = 'N';
    } else if (answers.XCP === 'unknown') {
      confidentialityImpacts.XCP = 'H';
    }
  }
  
  // Q2.C to Q6.C - Other categories
  const otherConfidentialityQuestions = [
    { id: 'XCD', description: 'diagnosis/monitoring' },
    { id: 'XCT', description: 'therapy delivery' },
    { id: 'XCW', description: 'clinical workflow' },
    { id: 'XCS', description: 'private system' },
    { id: 'XCO', description: 'other critical' }
  ];
  
  otherConfidentialityQuestions.forEach(q => {
    if (answers[q.id]) {
      if (answers[q.id] === 'yes' || answers[q.id] === 'unknown') {
        confidentialityImpacts[q.id] = 'H';
      } else if (answers[q.id] === 'no') {
        confidentialityImpacts[q.id] = 'N';
      }
    }
  });
  
  // Extended questions Q7 & Q8 logic
  const impacts = Object.values(confidentialityImpacts).filter(v => v !== undefined);
  const XCH = impacts.some(impact => impact === 'H'); // Any High?
  const XCL = impacts.some(impact => impact === 'L'); // Any Low?
  
  // Final Confidentiality Impact determination
  if (XCH) {
    vector.C = 'H';
  } else if (XCL) {
    vector.C = 'L';
  } else if (impacts.length > 0) {
    vector.C = 'N';
  } else {
    // No answers provided - default to None
    vector.C = 'N';
  }
  
  // Integrity Impact - Extended Logic
  const integrityImpacts: { [key: string]: 'H' | 'L' | 'N' | undefined } = {};
  
  // Q1.I to Q6.I - All integrity questions
  const integrityQuestions = [
    { id: 'XIP', description: 'PHI/PII' },
    { id: 'XID', description: 'diagnosis/monitoring' },
    { id: 'XIT', description: 'therapy delivery' },
    { id: 'XIW', description: 'clinical workflow' },
    { id: 'XIS', description: 'private system' },
    { id: 'XIO', description: 'other critical' }
  ];
  
  integrityQuestions.forEach(q => {
    if (answers[q.id]) {
      if (answers[q.id] === 'yes' || answers[q.id] === 'unknown') {
        integrityImpacts[q.id] = 'H';
      } else if (answers[q.id] === 'no') {
        integrityImpacts[q.id] = 'N';
      }
    }
  });
  
  // Extended questions Q9 & Q10 logic
  const integrityImpactValues = Object.values(integrityImpacts).filter(v => v !== undefined);
  const XIH = integrityImpactValues.some(impact => impact === 'H'); // Any High?
  const XIL = integrityImpactValues.some(impact => impact === 'L'); // Any Low?
  
  // Final Integrity Impact determination
  if (XIH) {
    vector.I = 'H';
  } else if (XIL) {
    vector.I = 'L';
  } else if (integrityImpactValues.length > 0) {
    vector.I = 'N';
  } else {
    // No answers provided - default to None
    vector.I = 'N';
  }
  
  // Availability Impact - Extended Logic
  const availabilityImpacts: { [key: string]: 'H' | 'L' | 'N' | undefined } = {};
  
  // Q1.A to Q6.A - All availability questions
  const availabilityQuestions = [
    { id: 'XAP', description: 'PHI/PII' },
    { id: 'XAD', description: 'diagnosis/monitoring' },
    { id: 'XAT', description: 'therapy delivery' },
    { id: 'XAW', description: 'clinical workflow' },
    { id: 'XAS', description: 'private system' },
    { id: 'XAO', description: 'other critical' }
  ];
  
  availabilityQuestions.forEach(q => {
    if (answers[q.id]) {
      if (answers[q.id] === 'yes' || answers[q.id] === 'unknown') {
        availabilityImpacts[q.id] = 'H';
      } else if (answers[q.id] === 'no') {
        availabilityImpacts[q.id] = 'N';
      }
    }
  });
  
  // Extended questions Q11 & Q12 logic
  const availabilityImpactValues = Object.values(availabilityImpacts).filter(v => v !== undefined);
  const XAH = availabilityImpactValues.some(impact => impact === 'H'); // Any High?
  const XAL = availabilityImpactValues.some(impact => impact === 'L'); // Any Low?
  
  // Final Availability Impact determination
  if (XAH) {
    vector.A = 'H';
  } else if (XAL) {
    vector.A = 'L';
  } else if (availabilityImpactValues.length > 0) {
    vector.A = 'N';
  } else {
    // No answers provided - default to None
    vector.A = 'N';
  }
  
  return vector;
};

export const getNextQuestion = (currentQuestion: string, answer: string): string | null => {
  const question = mitreRubricQuestions.find(q => q.id === currentQuestion);
  if (!question) return null;
  
  const option = question.options.find(o => o.value === answer);
  return option?.nextQuestion || null;
};