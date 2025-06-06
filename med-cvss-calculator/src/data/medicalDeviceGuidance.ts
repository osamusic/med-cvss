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
      description:
        'Attack Vector reflects the context by which vulnerability exploitation is possible.',
      medicalDeviceContext:
        'For medical devices, consider network connectivity, wireless interfaces, and physical access requirements.',
      examples: [
        'Network-connected infusion pumps',
        'Bluetooth-enabled glucose monitors',
        'Bedside monitors with local interfaces',
        'Implantable devices requiring physical contact',
      ],
    },
    options: [
      {
        value: 'N',
        guidance:
          'The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed below.',
        medicalExample:
          'Internet-connected patient monitoring systems, telemedicine devices accessible over hospital networks',
      },
      {
        value: 'A',
        guidance:
          'The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.',
        medicalExample:
          'WiFi-enabled medical devices, Bluetooth medical sensors, devices on the same network segment',
      },
      {
        value: 'L',
        guidance:
          "The vulnerable component is not bound to the network stack and the attacker's path is via read/write/execute capabilities.",
        medicalExample:
          'Medical devices requiring local login, USB-connected diagnostic equipment, bedside terminal access',
      },
      {
        value: 'P',
        guidance:
          'The attack requires the attacker to physically touch or manipulate the vulnerable component.',
        medicalExample:
          'Implantable devices, medical devices requiring physical port access, devices with physical maintenance interfaces',
      },
    ],
  },
  AC: {
    general: {
      description:
        "Attack Complexity describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability.",
      medicalDeviceContext:
        'Consider device configuration complexity, timing requirements, and specialized knowledge needed for medical devices.',
      examples: [
        'Device-specific protocols',
        'Clinical workflow timing',
        'Medical device authentication',
        'Specialized medical knowledge requirements',
      ],
    },
    options: [
      {
        value: 'L',
        guidance: 'Specialized access conditions or extenuating circumstances do not exist.',
        medicalExample:
          'Standard network protocols, default configurations, no specialized medical knowledge required',
      },
      {
        value: 'H',
        guidance: "A successful attack depends on conditions beyond the attacker's control.",
        medicalExample:
          'Device-specific protocols, specific clinical workflows, specialized medical training required, precise timing during procedures',
      },
    ],
  },
  PR: {
    general: {
      description:
        'Privileges Required describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.',
      medicalDeviceContext:
        'Consider medical device user roles, clinical privileges, and administrative access levels.',
      examples: [
        'Patient vs. clinician accounts',
        'Biomedical engineer access',
        'Hospital administrator privileges',
        'Device maintenance accounts',
      ],
    },
    options: [
      {
        value: 'N',
        guidance:
          'The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.',
        medicalExample:
          'Unauthenticated access to patient monitors, open network services, public-facing medical applications',
      },
      {
        value: 'L',
        guidance: 'The attacker requires privileges that provide basic user capabilities.',
        medicalExample:
          'Standard clinical user account, basic patient access privileges, limited device operation rights',
      },
      {
        value: 'H',
        guidance:
          'The attacker requires privileges that provide significant control over the vulnerable component.',
        medicalExample:
          'Biomedical engineering access, hospital IT administrator, device maintenance technician, clinical supervisor',
      },
    ],
  },
  UI: {
    general: {
      description:
        'User Interaction captures the requirement for a human user, other than the attacker, to participate in the successful compromise.',
      medicalDeviceContext:
        'Consider clinical workflows, patient interactions, and medical staff actions required for exploitation.',
      examples: [
        'Clinical staff actions',
        'Patient device interactions',
        'Automated medical processes',
        'Emergency response scenarios',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'The vulnerable system can be exploited without interaction from any user.',
        medicalExample:
          'Automated medical device processes, background network services, scheduled medical data transfers',
      },
      {
        value: 'R',
        guidance:
          'Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.',
        medicalExample:
          'Clinical staff opening malicious files, patients interacting with compromised interfaces, medical personnel connecting infected devices',
      },
    ],
  },
  S: {
    general: {
      description:
        'Scope captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope.',
      medicalDeviceContext:
        'Consider if exploitation affects multiple medical systems, patient data across devices, or hospital network components.',
      examples: [
        'Hospital network isolation',
        'Medical device segmentation',
        'Patient data system boundaries',
        'Clinical workflow integration',
      ],
    },
    options: [
      {
        value: 'U',
        guidance:
          'An exploited vulnerability can only affect resources managed by the same security authority.',
        medicalExample:
          'Impact limited to single medical device, isolated patient monitor, standalone diagnostic equipment',
      },
      {
        value: 'C',
        guidance:
          'An exploited vulnerability can affect resources beyond the security scope managed by the vulnerable component.',
        medicalExample:
          'Medical device compromise affects hospital network, patient data systems compromise, multiple connected medical devices affected',
      },
    ],
  },
  C: {
    general: {
      description:
        'Confidentiality measures the impact to the confidentiality of the information resources managed by a software component.',
      medicalDeviceContext:
        'Consider patient privacy, medical records access, and healthcare data protection requirements under HIPAA and other regulations.',
      examples: [
        'Patient health information (PHI)',
        'Medical imaging data',
        'Clinical notes and observations',
        'Treatment history and medications',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no loss of confidentiality within the impacted component.',
        medicalExample:
          'No patient data exposed, system logs only, device status information without patient details',
      },
      {
        value: 'L',
        guidance: 'There is some loss of confidentiality.',
        medicalExample:
          'Limited patient identifiers exposed, partial medical records access, non-sensitive clinical data',
      },
      {
        value: 'H',
        guidance:
          'There is a total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker.',
        medicalExample:
          'Complete patient medical records exposed, full access to PHI, medical imaging and diagnostic data compromised',
      },
    ],
  },
  I: {
    general: {
      description:
        'Integrity measures the impact to integrity of a successfully exploited vulnerability.',
      medicalDeviceContext:
        'Consider the impact on medical data accuracy, treatment protocols, and clinical decision-making if data is modified.',
      examples: [
        'Medical record modifications',
        'Treatment dose alterations',
        'Diagnostic result tampering',
        'Clinical protocol changes',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no loss of integrity within the impacted component.',
        medicalExample:
          'Medical data remains unmodified, read-only access to patient information, no clinical impact',
      },
      {
        value: 'L',
        guidance:
          'Modification of data is possible, but the attacker does not have control over the consequence of a modification.',
        medicalExample:
          'Limited medical record changes, minor configuration modifications, non-critical clinical data alteration',
      },
      {
        value: 'H',
        guidance: 'There is a total loss of integrity, or a complete loss of protection.',
        medicalExample:
          'Critical medical data modification, treatment protocol tampering, diagnostic results falsification affecting patient care',
      },
    ],
  },
  A: {
    general: {
      description:
        'Availability refers to the loss of availability of the impacted component itself.',
      medicalDeviceContext:
        'Consider the impact on patient care, emergency medical situations, and critical medical device functionality.',
      examples: [
        'Life-support system disruption',
        'Critical care monitoring outages',
        'Emergency medical equipment failure',
        'Patient monitoring interruptions',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no impact to availability within the impacted component.',
        medicalExample:
          'Medical device remains fully operational, no clinical workflow disruption, backup systems unaffected',
      },
      {
        value: 'L',
        guidance: 'Performance is reduced or there are interruptions in resource availability.',
        medicalExample:
          'Reduced medical device performance, intermittent monitoring capabilities, non-critical system slowdowns',
      },
      {
        value: 'H',
        guidance:
          'There is a total loss of availability, resulting in the attacker being able to fully deny access to resources.',
        medicalExample:
          'Complete medical device shutdown, life-support system failure, critical patient monitoring unavailable, emergency equipment offline',
      },
    ],
  },
  E: {
    general: {
      description:
        'Exploit Code Maturity measures the likelihood of the vulnerability being attacked, based on the current state of exploit techniques and code availability.',
      medicalDeviceContext:
        'Consider the availability of medical device exploits, regulatory reporting requirements, and healthcare-specific attack tools.',
      examples: [
        'Published medical device exploits',
        'Healthcare security research demonstrations',
        'FDA safety communications',
        'Medical device threat intelligence',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Exploit Code Maturity is not defined or is not applicable.',
        medicalExample:
          'No specific exploit assessment available, default scoring for medical device vulnerability assessments',
      },
      {
        value: 'U',
        guidance:
          'No exploit code is available, or an exploit is theoretical with no proof of concept available.',
        medicalExample:
          'Theoretical medical device vulnerability, unpublished research findings, internal security assessments only',
      },
      {
        value: 'P',
        guidance:
          'Proof-of-concept exploit code is available, or an attack demonstration is not practical for most systems.',
        medicalExample:
          'Medical device security research publications, controlled lab demonstrations, healthcare conference presentations',
      },
      {
        value: 'F',
        guidance:
          'Functional exploit code is available that works in most situations where the vulnerability exists.',
        medicalExample:
          'Working medical device exploits in circulation, healthcare-specific attack tools, documented successful attacks',
      },
      {
        value: 'H',
        guidance:
          'Functional autonomous code exists, or no exploit is required and details are widely available.',
        medicalExample:
          'Automated medical device attack tools, widely known healthcare vulnerabilities, active exploitation in healthcare facilities',
      },
    ],
  },
  RL: {
    general: {
      description:
        'Remediation Level indicates the availability of patches, workarounds, or fixes for a vulnerability.',
      medicalDeviceContext:
        'Consider FDA approval requirements for medical device updates, clinical validation needs, and healthcare deployment timelines.',
      examples: [
        'FDA-approved device patches',
        'Clinical workaround procedures',
        'Manufacturer security updates',
        'Compensating security controls',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Remediation Level is not defined or is not applicable.',
        medicalExample:
          'No remediation assessment available, default scoring for initial medical device vulnerability reporting',
      },
      {
        value: 'O',
        guidance: 'A complete vendor solution is available, either a vendor patch or an upgrade.',
        medicalExample:
          'FDA-approved medical device patch available, manufacturer security update released, validated device firmware upgrade',
      },
      {
        value: 'T',
        guidance:
          'There is an official but temporary fix available, including temporary hotfixes or workarounds.',
        medicalExample:
          'Temporary clinical workaround approved, interim security controls in place, manufacturer advisory with temporary mitigation',
      },
      {
        value: 'W',
        guidance:
          'There is an unofficial, non-vendor solution available, such as a workaround or mitigation created by users.',
        medicalExample:
          'Healthcare facility-developed workarounds, clinical procedure modifications, network isolation measures, third-party security controls',
      },
      {
        value: 'U',
        guidance: 'There is either no solution available or it is impossible to apply.',
        medicalExample:
          'No patch available for legacy medical devices, FDA approval pending for updates, end-of-life medical equipment',
      },
    ],
  },
  RC: {
    general: {
      description:
        'Report Confidence measures the degree of confidence in the existence of the vulnerability and credibility of the known technical details.',
      medicalDeviceContext:
        'Consider medical device security research validation, FDA alerts, manufacturer confirmations, and healthcare ISAC reports.',
      examples: [
        'FDA safety communications',
        'Manufacturer security advisories',
        'Healthcare security research papers',
        'Clinical incident reports',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Report Confidence is not defined or is not applicable.',
        medicalExample:
          'No confidence assessment available, default scoring for medical device vulnerability tracking',
      },
      {
        value: 'U',
        guidance:
          'There are reports of impacts that indicate a vulnerability is present, but the cause is unknown.',
        medicalExample:
          'Unexplained medical device behaviors reported, unconfirmed clinical incidents, anecdotal healthcare security concerns',
      },
      {
        value: 'R',
        guidance:
          'Significant details are published, but researchers either do not have full confidence or do not have access to source code.',
        medicalExample:
          'Medical device security research with partial validation, third-party healthcare security assessments, clinical testing results',
      },
      {
        value: 'C',
        guidance:
          'Detailed reports exist, or functional reproduction is possible, or the vulnerability is confirmed by the vendor.',
        medicalExample:
          'Manufacturer-confirmed vulnerability, FDA-validated security issue, peer-reviewed medical device research, reproducible clinical testing',
      },
    ],
  },
  CR: {
    general: {
      description:
        'Confidentiality Requirement represents the criticality of maintaining the confidentiality of the affected IT asset.',
      medicalDeviceContext:
        'Consider HIPAA requirements, patient privacy regulations, medical record confidentiality, and healthcare data protection standards.',
      examples: [
        'Patient health information (PHI) protection',
        'Medical record privacy requirements',
        'Clinical trial data confidentiality',
        'Healthcare compliance mandates',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Confidentiality Requirement is not defined or is not applicable.',
        medicalExample:
          'Default environmental scoring, no specific confidentiality assessment for this medical system',
      },
      {
        value: 'L',
        guidance:
          'Loss of confidentiality is likely to have only a limited adverse effect on the organization.',
        medicalExample:
          'Non-patient device telemetry data, aggregated healthcare statistics, publicly available clinical protocols',
      },
      {
        value: 'M',
        guidance:
          'Loss of confidentiality is likely to have a serious adverse effect on the organization.',
        medicalExample:
          'Limited patient demographics, clinical scheduling information, non-critical medical device configurations',
      },
      {
        value: 'H',
        guidance:
          'Loss of confidentiality is likely to have a catastrophic adverse effect on the organization.',
        medicalExample:
          'Protected health information (PHI), complete medical records, clinical trial data, sensitive diagnostic results',
      },
    ],
  },
  IR: {
    general: {
      description:
        'Integrity Requirement represents the criticality of maintaining the trustworthiness and correctness of the affected IT asset.',
      medicalDeviceContext:
        'Consider the impact on clinical decision-making, treatment accuracy, medical data reliability, and patient safety if data is modified.',
      examples: [
        'Treatment protocol integrity',
        'Medical dosage accuracy',
        'Diagnostic data reliability',
        'Clinical decision support integrity',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Integrity Requirement is not defined or is not applicable.',
        medicalExample:
          'Default environmental scoring, no specific integrity assessment for this medical system',
      },
      {
        value: 'L',
        guidance:
          'Loss of integrity is likely to have only a limited adverse effect on the organization.',
        medicalExample:
          'Non-clinical administrative data, medical device logs, healthcare facility schedules, reference documentation',
      },
      {
        value: 'M',
        guidance:
          'Loss of integrity is likely to have a serious adverse effect on the organization.',
        medicalExample:
          'Clinical notes accuracy, medical billing information, device calibration data, quality metrics',
      },
      {
        value: 'H',
        guidance:
          'Loss of integrity is likely to have a catastrophic adverse effect on the organization.',
        medicalExample:
          'Medication dosages, treatment protocols, diagnostic results, surgical parameters, life-support settings',
      },
    ],
  },
  AR: {
    general: {
      description:
        'Availability Requirement represents the criticality of the affected IT asset to the user organization in terms of availability.',
      medicalDeviceContext:
        'Consider the impact on patient care continuity, emergency medical services, life-critical systems, and healthcare operations.',
      examples: [
        'Life-support system availability',
        'Emergency department operations',
        'Critical care monitoring uptime',
        'Surgical equipment readiness',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Availability Requirement is not defined or is not applicable.',
        medicalExample:
          'Default environmental scoring, no specific availability assessment for this medical system',
      },
      {
        value: 'L',
        guidance:
          'Loss of availability is likely to have only a limited adverse effect on the organization.',
        medicalExample:
          'Administrative healthcare systems, non-critical medical reference systems, elective procedure scheduling, training equipment',
      },
      {
        value: 'M',
        guidance:
          'Loss of availability is likely to have a serious adverse effect on the organization.',
        medicalExample:
          'Standard patient monitoring, routine diagnostic equipment, clinical documentation systems, pharmacy systems',
      },
      {
        value: 'H',
        guidance:
          'Loss of availability is likely to have a catastrophic adverse effect on the organization.',
        medicalExample:
          'Life-support systems, emergency medical equipment, critical care monitors, surgical devices, emergency department systems',
      },
    ],
  },
  // CVSS v4.0 specific metrics
  AT: {
    general: {
      description:
        'Attack Requirements captures the additional deployment and execution conditions or variables of the vulnerable system that enable the attack.',
      medicalDeviceContext:
        'Consider special medical device configurations, clinical workflow dependencies, and timing requirements for exploitation.',
      examples: [
        'Device-specific clinical modes',
        'Medical procedure timing dependencies',
        'Patient state requirements',
        'Clinical authentication contexts',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There are no conditions that must be met for successful exploitation.',
        medicalExample:
          'Medical device vulnerability exploitable in any operational state, no specific clinical context required',
      },
      {
        value: 'P',
        guidance:
          'The successful attack depends on the evasion or circumvention of security-enhancing conditions or requires race conditions.',
        medicalExample:
          'Exploitation requires specific clinical workflow timing, device in maintenance mode, during patient procedure, or specific medical protocol execution',
      },
    ],
  },
  VC: {
    general: {
      description:
        'Vulnerable System Confidentiality Impact measures the impact to the confidentiality of the information managed by the vulnerable system.',
      medicalDeviceContext:
        'Consider patient privacy on the directly compromised medical device, device-specific medical data, and local patient information.',
      examples: [
        'Patient data on the device',
        'Medical device logs and telemetry',
        'Device configuration and settings',
        'Local clinical observations',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no loss of confidentiality within the vulnerable system.',
        medicalExample:
          'Device status information only, no patient data on the vulnerable medical device, anonymized telemetry',
      },
      {
        value: 'L',
        guidance: 'There is some loss of confidentiality.',
        medicalExample:
          'Limited patient identifiers on device, partial medical readings, device usage patterns, non-sensitive clinical data',
      },
      {
        value: 'H',
        guidance: 'There is total loss of confidentiality within the vulnerable system.',
        medicalExample:
          'Complete patient medical data on device, full access to device-stored PHI, medical images and diagnostic data on the system',
      },
    ],
  },
  VI: {
    general: {
      description:
        'Vulnerable System Integrity Impact measures the impact to integrity of the vulnerable system.',
      medicalDeviceContext:
        'Consider the impact on medical device data accuracy, device configuration integrity, and clinical data reliability on the affected system.',
      examples: [
        'Device configuration tampering',
        'Medical data modification on device',
        'Calibration data alteration',
        'Device operational parameters',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no loss of integrity within the vulnerable system.',
        medicalExample:
          'Medical device data remains unmodified, read-only access to device information, no configuration changes possible',
      },
      {
        value: 'L',
        guidance: 'Modification of data is possible, but with limited control over consequences.',
        medicalExample:
          'Minor device configuration changes, limited medical data modification, non-critical parameter adjustments',
      },
      {
        value: 'H',
        guidance: 'There is total loss of integrity within the vulnerable system.',
        medicalExample:
          'Complete control over device settings, medical data falsification, critical parameter modification, calibration tampering',
      },
    ],
  },
  VA: {
    general: {
      description:
        'Vulnerable System Availability Impact measures the impact to the availability of the vulnerable system.',
      medicalDeviceContext:
        'Consider the impact on the specific medical device functionality, clinical workflow disruption, and patient care delivery.',
      examples: [
        'Medical device operational disruption',
        'Clinical workflow interruption',
        'Patient monitoring gaps',
        'Treatment delivery interference',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no impact to availability within the vulnerable system.',
        medicalExample:
          'Medical device remains fully operational, no clinical workflow disruption, all functions available',
      },
      {
        value: 'L',
        guidance: 'Performance is reduced or there are interruptions in resource availability.',
        medicalExample:
          'Reduced device performance, intermittent functionality, delayed medical readings, non-critical feature unavailable',
      },
      {
        value: 'H',
        guidance: 'There is total loss of availability within the vulnerable system.',
        medicalExample:
          'Complete device shutdown, medical equipment failure, total loss of clinical functionality, patient monitoring unavailable',
      },
    ],
  },
  SC: {
    general: {
      description:
        'Subsequent System Confidentiality Impact measures the impact to the confidentiality of information managed by other systems.',
      medicalDeviceContext:
        'Consider impact on other medical systems, hospital networks, electronic health records, and connected healthcare infrastructure.',
      examples: [
        'Hospital network data exposure',
        'Electronic health record access',
        'Connected medical device data',
        'Healthcare system integration points',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no loss of confidentiality in subsequent systems.',
        medicalExample:
          'Isolated medical device with no network connectivity, no impact on other healthcare systems, segmented clinical network',
      },
      {
        value: 'L',
        guidance: 'There is some loss of confidentiality in subsequent systems.',
        medicalExample:
          'Limited access to connected medical devices, partial network data exposure, restricted healthcare system access',
      },
      {
        value: 'H',
        guidance: 'There is total loss of confidentiality in subsequent systems.',
        medicalExample:
          'Full hospital network compromise, complete EHR system access, widespread medical device data exposure, healthcare infrastructure breach',
      },
    ],
  },
  SI: {
    general: {
      description:
        'Subsequent System Integrity Impact measures the impact to the integrity of information managed by other systems.',
      medicalDeviceContext:
        'Consider impact on other medical systems, treatment protocols across devices, and healthcare data consistency.',
      examples: [
        'Cross-system medical data integrity',
        'Treatment protocol consistency',
        'Healthcare database modifications',
        'Clinical decision support corruption',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no loss of integrity in subsequent systems.',
        medicalExample:
          'No impact on other healthcare systems, isolated device modification only, network segmentation prevents spread',
      },
      {
        value: 'L',
        guidance: 'Modification of data is possible in subsequent systems with limited control.',
        medicalExample:
          'Limited changes to connected medical devices, minor healthcare database modifications, restricted protocol alterations',
      },
      {
        value: 'H',
        guidance: 'There is total loss of integrity in subsequent systems.',
        medicalExample:
          'Widespread medical system manipulation, critical treatment protocol tampering, healthcare database corruption, clinical decision support compromise',
      },
    ],
  },
  SA: {
    general: {
      description:
        'Subsequent System Availability Impact measures the impact to the availability of other systems.',
      medicalDeviceContext:
        'Consider impact on hospital operations, connected medical devices, emergency systems, and overall healthcare delivery.',
      examples: [
        'Hospital-wide system outages',
        'Connected medical device failures',
        'Emergency system disruptions',
        'Healthcare network unavailability',
      ],
    },
    options: [
      {
        value: 'N',
        guidance: 'There is no impact to availability in subsequent systems.',
        medicalExample:
          'No impact on other healthcare systems, isolated device only, redundant systems maintain operations',
      },
      {
        value: 'L',
        guidance: 'Performance is reduced or there are interruptions in subsequent systems.',
        medicalExample:
          'Reduced performance of connected medical devices, intermittent healthcare system availability, partial network degradation',
      },
      {
        value: 'H',
        guidance: 'There is total loss of availability in subsequent systems.',
        medicalExample:
          'Hospital-wide system failures, emergency equipment unavailable, complete healthcare network outage, critical care system shutdown',
      },
    ],
  },
};
