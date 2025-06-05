export interface RubricQuestion {
  id: string;
  text: string;
  category: string;
  subcategory?: string;
  options: {
    value: 'yes' | 'no' | 'unknown';
    label: string;
  }[];
}

export interface RubricCategory {
  name: string;
  description: string;
  questions: RubricQuestion[];
}

export interface RubricAnswers {
  [questionId: string]: 'yes' | 'no' | 'unknown';
}

export const rubricCategories: RubricCategory[] = [
  {
    name: "Attack Vector (AV)",
    description: "This metric reflects the context by which vulnerability exploitation is possible.",
    questions: [
      {
        id: "Q1",
        text: "Can this vulnerability be exploited remotely over a network?",
        category: "AV",
        options: [
          { value: "yes", label: "Yes - Network accessible" },
          { value: "no", label: "No - Requires local/physical access" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q2", 
        text: "Does exploitation require adjacent network access (e.g., Bluetooth, WiFi)?",
        category: "AV",
        options: [
          { value: "yes", label: "Yes - Adjacent network required" },
          { value: "no", label: "No - Network or local access" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q3",
        text: "Does exploitation require physical access to the device?",
        category: "AV", 
        options: [
          { value: "yes", label: "Yes - Physical access required" },
          { value: "no", label: "No - Remote access possible" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  },
  {
    name: "Attack Complexity (AC)",
    description: "This metric describes the conditions beyond the attacker's control that must exist.",
    questions: [
      {
        id: "Q4",
        text: "Can this vulnerability be exploited reliably and repeatedly?",
        category: "AC",
        options: [
          { value: "yes", label: "Yes - Reliable exploitation" },
          { value: "no", label: "No - Requires specific conditions" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q5",
        text: "Does exploitation require specialized conditions or timing?",
        category: "AC",
        options: [
          { value: "yes", label: "Yes - Specialized conditions needed" },
          { value: "no", label: "No - Simple exploitation" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  },
  {
    name: "Privileges Required (PR)",
    description: "This metric describes the level of privileges an attacker must possess.",
    questions: [
      {
        id: "Q6",
        text: "Can this vulnerability be exploited without any authentication?",
        category: "PR",
        options: [
          { value: "yes", label: "Yes - No authentication required" },
          { value: "no", label: "No - Authentication required" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q7",
        text: "Does exploitation require administrative or high-level privileges?",
        category: "PR",
        options: [
          { value: "yes", label: "Yes - High privileges required" },
          { value: "no", label: "No - Low/no privileges needed" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  },
  {
    name: "User Interaction (UI)",
    description: "This metric captures the requirement for a human user to participate in the attack.",
    questions: [
      {
        id: "Q8",
        text: "Can this vulnerability be exploited without any user interaction?",
        category: "UI",
        options: [
          { value: "yes", label: "Yes - No user interaction required" },
          { value: "no", label: "No - User interaction required" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  },
  {
    name: "Scope (S)",
    description: "This metric captures whether a vulnerability in one vulnerable component impacts resources beyond its security scope.",
    questions: [
      {
        id: "Q9",
        text: "Does exploitation of this vulnerability impact resources beyond the vulnerable component?",
        category: "S",
        options: [
          { value: "yes", label: "Yes - Impact extends beyond component" },
          { value: "no", label: "No - Impact limited to component" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  },
  {
    name: "Confidentiality Impact (C)",
    description: "This metric measures the impact to the confidentiality of information resources.",
    questions: [
      {
        id: "Q10",
        text: "Can this vulnerability lead to disclosure of patient health information (PHI/PII)?",
        category: "C",
        subcategory: "PHI/PII",
        options: [
          { value: "yes", label: "Yes - PHI/PII disclosure possible" },
          { value: "no", label: "No - No PHI/PII disclosure" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q11",
        text: "Can this vulnerability lead to disclosure of diagnostic data?",
        category: "C",
        subcategory: "Diagnostic",
        options: [
          { value: "yes", label: "Yes - Diagnostic data disclosure" },
          { value: "no", label: "No - No diagnostic data disclosure" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q12",
        text: "Can this vulnerability lead to disclosure of device configuration or security information?",
        category: "C",
        subcategory: "Configuration",
        options: [
          { value: "yes", label: "Yes - Configuration disclosure" },
          { value: "no", label: "No - No configuration disclosure" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  },
  {
    name: "Integrity Impact (I)",
    description: "This metric measures the impact to integrity of a successfully exploited vulnerability.",
    questions: [
      {
        id: "Q13",
        text: "Can this vulnerability lead to modification of patient data or medical records?",
        category: "I",
        subcategory: "Patient Data",
        options: [
          { value: "yes", label: "Yes - Patient data modification" },
          { value: "no", label: "No - No patient data modification" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q14",
        text: "Can this vulnerability lead to modification of therapeutic parameters or treatment settings?",
        category: "I", 
        subcategory: "Therapeutic",
        options: [
          { value: "yes", label: "Yes - Therapeutic modification" },
          { value: "no", label: "No - No therapeutic modification" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q15",
        text: "Can this vulnerability lead to modification of device firmware or software?",
        category: "I",
        subcategory: "Device",
        options: [
          { value: "yes", label: "Yes - Device modification" },
          { value: "no", label: "No - No device modification" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  },
  {
    name: "Availability Impact (A)",
    description: "This metric measures the impact to the availability of the impacted component.",
    questions: [
      {
        id: "Q16",
        text: "Can this vulnerability cause complete loss of availability of critical medical functions?",
        category: "A",
        subcategory: "Critical Functions",
        options: [
          { value: "yes", label: "Yes - Critical function loss" },
          { value: "no", label: "No - No critical function impact" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q17",
        text: "Can this vulnerability cause performance degradation of medical device services?",
        category: "A",
        subcategory: "Performance",
        options: [
          { value: "yes", label: "Yes - Performance degradation" },
          { value: "no", label: "No - No performance impact" },
          { value: "unknown", label: "Unknown" }
        ]
      },
      {
        id: "Q18",
        text: "Can this vulnerability cause workflow disruption in clinical operations?",
        category: "A",
        subcategory: "Workflow",
        options: [
          { value: "yes", label: "Yes - Workflow disruption" },
          { value: "no", label: "No - No workflow impact" },
          { value: "unknown", label: "Unknown" }
        ]
      }
    ]
  }
];

export const calculateRubricVector = (answers: RubricAnswers): { [key: string]: string } => {
  const vector: { [key: string]: string } = {};
  
  // Attack Vector logic
  if (answers.Q1 === 'yes') {
    vector.AV = 'N'; // Network
  } else if (answers.Q2 === 'yes') {
    vector.AV = 'A'; // Adjacent 
  } else if (answers.Q3 === 'yes') {
    vector.AV = 'P'; // Physical
  } else {
    vector.AV = 'L'; // Local (default)
  }
  
  // Attack Complexity logic
  if (answers.Q4 === 'yes' && answers.Q5 === 'no') {
    vector.AC = 'L'; // Low complexity
  } else {
    vector.AC = 'H'; // High complexity
  }
  
  // Privileges Required logic
  if (answers.Q6 === 'yes') {
    vector.PR = 'N'; // None required
  } else if (answers.Q7 === 'yes') {
    vector.PR = 'H'; // High privileges
  } else {
    vector.PR = 'L'; // Low privileges
  }
  
  // User Interaction logic
  if (answers.Q8 === 'yes') {
    vector.UI = 'N'; // None required
  } else {
    vector.UI = 'R'; // Required
  }
  
  // Scope logic
  if (answers.Q9 === 'yes') {
    vector.S = 'C'; // Changed
  } else {
    vector.S = 'U'; // Unchanged
  }
  
  // Confidentiality Impact logic
  if (answers.Q10 === 'yes' || answers.Q11 === 'yes' || answers.Q12 === 'yes') {
    // If any confidentiality question is yes, determine severity
    if (answers.Q10 === 'yes') {
      vector.C = 'H'; // High for PHI/PII
    } else if (answers.Q11 === 'yes') {
      vector.C = 'L'; // Low for diagnostic data
    } else {
      vector.C = 'L'; // Low for configuration
    }
  } else {
    vector.C = 'N'; // None
  }
  
  // Integrity Impact logic
  if (answers.Q13 === 'yes' || answers.Q14 === 'yes') {
    vector.I = 'H'; // High for patient data or therapeutic
  } else if (answers.Q15 === 'yes') {
    vector.I = 'L'; // Low for device modification
  } else {
    vector.I = 'N'; // None
  }
  
  // Availability Impact logic
  if (answers.Q16 === 'yes') {
    vector.A = 'H'; // High for critical functions
  } else if (answers.Q17 === 'yes' || answers.Q18 === 'yes') {
    vector.A = 'L'; // Low for performance/workflow
  } else {
    vector.A = 'N'; // None
  }
  
  return vector;
};