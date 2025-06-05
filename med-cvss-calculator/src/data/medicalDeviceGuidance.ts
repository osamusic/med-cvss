export interface MetricGuidance {
  description: string;
  medicalDeviceContext: string;
  examples: string[];
}

export interface MetricOptionGuidance {
  value: string;
  guidance: string;
  medicalExample: string;
}

export interface CVSSMetricGuidance {
  [metricKey: string]: {
    general: MetricGuidance;
    options: MetricOptionGuidance[];
  };
}

export const medicalDeviceGuidance: CVSSMetricGuidance = {
  AV: {
    general: {
      description: "Attack Vector reflects the context by which vulnerability exploitation is possible.",
      medicalDeviceContext: "For medical devices, consider network connectivity, wireless interfaces, and physical access requirements.",
      examples: [
        "Network-connected infusion pumps",
        "Bluetooth-enabled glucose monitors", 
        "Bedside monitors with local interfaces",
        "Implantable devices requiring physical contact"
      ]
    },
    options: [
      {
        value: "N",
        guidance: "The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below.",
        medicalExample: "Internet-connected patient monitoring systems, telemedicine devices accessible over hospital networks"
      },
      {
        value: "A", 
        guidance: "The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.",
        medicalExample: "WiFi-enabled medical devices, Bluetooth medical sensors, devices on the same network segment"
      },
      {
        value: "L",
        guidance: "The vulnerable component is not bound to the network stack and the attacker's path is via read/write/execute capabilities.",
        medicalExample: "Medical devices requiring local login, USB-connected diagnostic equipment, bedside terminal access"
      },
      {
        value: "P",
        guidance: "The attack requires the attacker to physically touch or manipulate the vulnerable component.",
        medicalExample: "Implantable devices, medical devices requiring physical port access, devices with physical maintenance interfaces"
      }
    ]
  },
  AC: {
    general: {
      description: "Attack Complexity describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability.",
      medicalDeviceContext: "Consider device configuration complexity, timing requirements, and specialized knowledge needed for medical devices.",
      examples: [
        "Device-specific protocols",
        "Clinical workflow timing",
        "Medical device authentication",
        "Specialized medical knowledge requirements"
      ]
    },
    options: [
      {
        value: "L",
        guidance: "Specialized access conditions or extenuating circumstances do not exist.",
        medicalExample: "Standard network protocols, default configurations, no specialized medical knowledge required"
      },
      {
        value: "H", 
        guidance: "A successful attack depends on conditions beyond the attacker's control.",
        medicalExample: "Device-specific protocols, specific clinical workflows, specialized medical training required, precise timing during procedures"
      }
    ]
  },
  PR: {
    general: {
      description: "Privileges Required describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.",
      medicalDeviceContext: "Consider medical device user roles, clinical privileges, and administrative access levels.",
      examples: [
        "Patient vs. clinician accounts",
        "Biomedical engineer access",
        "Hospital administrator privileges",
        "Device maintenance accounts"
      ]
    },
    options: [
      {
        value: "N",
        guidance: "The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.",
        medicalExample: "Unauthenticated access to patient monitors, open network services, public-facing medical applications"
      },
      {
        value: "L",
        guidance: "The attacker requires privileges that provide basic user capabilities.",
        medicalExample: "Standard clinical user account, basic patient access privileges, limited device operation rights"
      },
      {
        value: "H",
        guidance: "The attacker requires privileges that provide significant control over the vulnerable component.",
        medicalExample: "Biomedical engineering access, hospital IT administrator, device maintenance technician, clinical supervisor"
      }
    ]
  },
  UI: {
    general: {
      description: "User Interaction captures the requirement for a human user, other than the attacker, to participate in the successful compromise.",
      medicalDeviceContext: "Consider clinical workflows, patient interactions, and medical staff actions required for exploitation.",
      examples: [
        "Clinical staff actions",
        "Patient device interactions", 
        "Automated medical processes",
        "Emergency response scenarios"
      ]
    },
    options: [
      {
        value: "N",
        guidance: "The vulnerable system can be exploited without interaction from any user.",
        medicalExample: "Automated medical device processes, background network services, scheduled medical data transfers"
      },
      {
        value: "R",
        guidance: "Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.",
        medicalExample: "Clinical staff opening malicious files, patients interacting with compromised interfaces, medical personnel connecting infected devices"
      }
    ]
  },
  S: {
    general: {
      description: "Scope captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope.",
      medicalDeviceContext: "Consider if exploitation affects multiple medical systems, patient data across devices, or hospital network components.",
      examples: [
        "Hospital network isolation",
        "Medical device segmentation",
        "Patient data system boundaries",
        "Clinical workflow integration"
      ]
    },
    options: [
      {
        value: "U",
        guidance: "An exploited vulnerability can only affect resources managed by the same security authority.",
        medicalExample: "Impact limited to single medical device, isolated patient monitor, standalone diagnostic equipment"
      },
      {
        value: "C",
        guidance: "An exploited vulnerability can affect resources beyond the security scope managed by the vulnerable component.",
        medicalExample: "Medical device compromise affects hospital network, patient data systems compromise, multiple connected medical devices affected"
      }
    ]
  },
  C: {
    general: {
      description: "Confidentiality measures the impact to the confidentiality of the information resources managed by a software component.",
      medicalDeviceContext: "Consider patient privacy, medical records access, and healthcare data protection requirements under HIPAA and other regulations.",
      examples: [
        "Patient health information (PHI)",
        "Medical imaging data",
        "Clinical notes and observations",
        "Treatment history and medications"
      ]
    },
    options: [
      {
        value: "N",
        guidance: "There is no loss of confidentiality within the impacted component.",
        medicalExample: "No patient data exposed, system logs only, device status information without patient details"
      },
      {
        value: "L",
        guidance: "There is some loss of confidentiality.",
        medicalExample: "Limited patient identifiers exposed, partial medical records access, non-sensitive clinical data"
      },
      {
        value: "H",
        guidance: "There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.",
        medicalExample: "Complete patient medical records exposed, full access to PHI, medical imaging and diagnostic data compromised"
      }
    ]
  },
  I: {
    general: {
      description: "Integrity measures the impact to integrity of a successfully exploited vulnerability.",
      medicalDeviceContext: "Consider the impact on medical data accuracy, treatment protocols, and clinical decision-making if data is modified.",
      examples: [
        "Medical record modifications",
        "Treatment dose alterations", 
        "Diagnostic result tampering",
        "Clinical protocol changes"
      ]
    },
    options: [
      {
        value: "N",
        guidance: "There is no loss of integrity within the impacted component.",
        medicalExample: "Medical data remains unmodified, read-only access to patient information, no clinical impact"
      },
      {
        value: "L",
        guidance: "Modification of data is possible, but the attacker does not have control over the consequence of a modification.",
        medicalExample: "Limited medical record changes, minor configuration modifications, non-critical clinical data alteration"
      },
      {
        value: "H",
        guidance: "There is a total loss of integrity, or a complete loss of protection.",
        medicalExample: "Critical medical data modification, treatment protocol tampering, diagnostic results falsification affecting patient care"
      }
    ]
  },
  A: {
    general: {
      description: "Availability refers to the loss of availability of the impacted component itself.",
      medicalDeviceContext: "Consider the impact on patient care, emergency medical situations, and critical medical device functionality.",
      examples: [
        "Life-support system disruption",
        "Critical care monitoring outages",
        "Emergency medical equipment failure",
        "Patient monitoring interruptions"
      ]
    },
    options: [
      {
        value: "N",
        guidance: "There is no impact to availability within the impacted component.",
        medicalExample: "Medical device remains fully operational, no clinical workflow disruption, backup systems unaffected"
      },
      {
        value: "L",
        guidance: "Performance is reduced or there are interruptions in resource availability.",
        medicalExample: "Reduced medical device performance, intermittent monitoring capabilities, non-critical system slowdowns"
      },
      {
        value: "H",
        guidance: "There is a total loss of availability, resulting in the attacker being able to fully deny access to resources.",
        medicalExample: "Complete medical device shutdown, life-support system failure, critical patient monitoring unavailable, emergency equipment offline"
      }
    ]
  }
};