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
        value: 'P',
        guidance:
          'Successful exploitation requires limited user interaction, performed during normal operation.',
        medicalExample:
          'Patient routine device usage, normal clinical workflow actions, standard medical device operations that trigger vulnerability',
      },
      {
        value: 'A',
        guidance:
          'Successful exploitation requires deliberate user interaction beyond normal operation.',
        medicalExample:
          'Clinical staff opening malicious files, patients interacting with specific compromised interfaces, medical personnel performing non-standard device procedures',
      },
      {
        value: 'R',
        guidance:
          'Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited (v3.1 compatibility).',
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
        'Exploit Maturity measures the likelihood of the vulnerability being attacked, based on the current state of exploit techniques and code availability (renamed from Exploit Code Maturity in v4.0).',
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
        guidance: 'The Exploit Maturity is not defined or is not applicable.',
        medicalExample:
          'No specific exploit assessment available, default scoring for medical device vulnerability assessments',
      },
      {
        value: 'U',
        guidance:
          'No reliable exploit exists or the vulnerability has not been reported publicly.',
        medicalExample:
          'Theoretical medical device vulnerability, unpublished research findings, internal security assessments only',
      },
      {
        value: 'P',
        guidance:
          'Proof-of-concept exploit code is available or an attack demonstration is practical for most systems.',
        medicalExample:
          'Medical device security research publications, controlled lab demonstrations, healthcare conference presentations',
      },
      {
        value: 'A',
        guidance:
          'Attacks have been reported against this vulnerability in the wild.',
        medicalExample:
          'Documented attacks on medical devices in clinical environments, healthcare security incidents, active exploitation in healthcare facilities',
      },
      {
        value: 'F',
        guidance:
          'Functional exploit code is available that works in most situations where the vulnerability exists (v3.1 compatibility).',
        medicalExample:
          'Working medical device exploits in circulation, healthcare-specific attack tools, documented successful attacks',
      },
      {
        value: 'H',
        guidance:
          'Functional autonomous code exists, or no exploit is required and details are widely available (v3.1 compatibility).',
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
  // CVSS v4.0 Supplemental Metrics (Optional)
  S: {
    general: {
      description:
        'Safety describes the potential for physical harm or threats to human life or safety resulting from exploitation of the vulnerability.',
      medicalDeviceContext:
        'Consider potential patient safety risks, physical harm to patients or healthcare workers, and life-threatening consequences from medical device compromise.',
      examples: [
        'Patient life support system failures',
        'Medical device malfunctions affecting patient safety',
        'Surgical equipment compromises during procedures',
        'Emergency medical equipment unavailability',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Safety metric is not defined or is not applicable.',
        medicalExample:
          'Default supplemental scoring, no specific safety assessment for this vulnerability',
      },
      {
        value: 'N',
        guidance:
          'The vulnerability consequences meet IEC 61508 definition of "negligible" safety impact.',
        medicalExample:
          'Administrative system compromise with no patient care impact, non-critical device telemetry failure, training equipment malfunction',
      },
      {
        value: 'P',
        guidance:
          'The vulnerability consequences meet IEC 61508 definitions of "marginal," "critical," or "catastrophic" safety impact.',
        medicalExample:
          'Life support system compromise, critical patient monitoring failure, surgical device malfunction during procedures, emergency equipment unavailability',
      },
    ],
  },
  AU: {
    general: {
      description:
        'Automatable captures whether attackers can reliably automate all four steps of the attack kill chain for this vulnerability.',
      medicalDeviceContext:
        'Consider whether medical device vulnerabilities can be exploited through automated scripts across multiple healthcare facilities.',
      examples: [
        'Automated scanning of medical device networks',
        'Script-based exploitation of device vulnerabilities',
        'Worm propagation through medical systems',
        'Automated credential harvesting from devices',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Automatable metric is not defined or is not applicable.',
        medicalExample:
          'Default supplemental scoring, no automation assessment available for this medical device vulnerability',
      },
      {
        value: 'N',
        guidance:
          'Attackers cannot reliably automate all four steps of the kill chain (reconnaissance, weaponization, delivery, exploitation).',
        medicalExample:
          'Requires physical access to medical devices, manual clinical workflow manipulation, device-specific manual configuration, healthcare staff social engineering',
      },
      {
        value: 'Y',
        guidance:
          'Attackers can reliably automate all four steps of the kill chain across multiple targets.',
        medicalExample:
          'Network-based medical device scanning and exploitation, automated credential attacks on healthcare systems, scripted malware deployment across hospital networks',
      },
    ],
  },
  R: {
    general: {
      description:
        'Recovery describes the resilience of a system to recover services in terms of performance and availability after an attack.',
      medicalDeviceContext:
        'Consider medical device recovery capabilities, clinical workflow restoration, and patient care continuity after security incidents.',
      examples: [
        'Medical device automatic restart capabilities',
        'Clinical workflow backup procedures',
        'Manual device recovery procedures',
        'Permanent medical equipment damage',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Recovery metric is not defined or is not applicable.',
        medicalExample:
          'Default supplemental scoring, no recovery assessment available for this medical system',
      },
      {
        value: 'A',
        guidance:
          'The system automatically recovers services after an attack with minimal or no administrator intervention.',
        medicalExample:
          'Medical devices with automatic restart and self-healing capabilities, redundant medical systems with failover, automatic clinical workflow restoration',
      },
      {
        value: 'U',
        guidance:
          'Manual user intervention is required to recover the system after an attack.',
        medicalExample:
          'Manual medical device restart procedures, clinical staff intervention required, device reconfiguration needed, manual patient data recovery',
      },
      {
        value: 'I',
        guidance:
          'The system cannot be recovered after an attack, requiring replacement or permanent loss of functionality.',
        medicalExample:
          'Permanent medical device damage, irreversible patient data loss, destroyed medical equipment requiring replacement, corrupted device firmware',
      },
    ],
  },
  V: {
    general: {
      description:
        'Value Density describes the resources that attackers will gain control over with a single exploitation event.',
      medicalDeviceContext:
        'Consider the concentration of medical resources, patient data, and healthcare infrastructure accessible through the vulnerable system.',
      examples: [
        'Centralized patient database systems',
        'Hospital-wide medical device networks',
        'Individual medical device resources',
        'Healthcare data concentration levels',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Value Density metric is not defined or is not applicable.',
        medicalExample:
          'Default supplemental scoring, no value density assessment for this medical system',
      },
      {
        value: 'D',
        guidance:
          'The system has limited resources, with diffuse value distribution.',
        medicalExample:
          'Individual medical devices with limited data, single-patient monitoring systems, isolated diagnostic equipment, standalone medical workstations',
      },
      {
        value: 'C',
        guidance:
          'The system is rich in resources, with concentrated high-value targets.',
        medicalExample:
          'Hospital-wide EHR systems, centralized medical device management platforms, comprehensive patient databases, critical healthcare infrastructure hubs',
      },
    ],
  },
  RE: {
    general: {
      description:
        'Vulnerability Response Effort describes how difficult it is for consumers to provide an initial response to the vulnerability impact.',
      medicalDeviceContext:
        'Consider healthcare facility capabilities, clinical workflow disruption, and regulatory requirements for responding to medical device vulnerabilities.',
      examples: [
        'Medical device patching complexity',
        'Clinical workflow adjustment requirements',
        'Regulatory compliance considerations',
        'Healthcare facility technical capabilities',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Vulnerability Response Effort metric is not defined or is not applicable.',
        medicalExample:
          'Default supplemental scoring, no response effort assessment for this medical vulnerability',
      },
      {
        value: 'L',
        guidance:
          'The effort required to respond to the vulnerability is low with minimal service impact.',
        medicalExample:
          'Simple device configuration changes, minor clinical workflow adjustments, standard IT patching procedures, minimal staff training required',
      },
      {
        value: 'M',
        guidance:
          'The effort required to respond involves moderate complexity with some service impact.',
        medicalExample:
          'Coordinated device updates during maintenance windows, clinical staff retraining, temporary procedure modifications, moderate healthcare IT resources',
      },
      {
        value: 'H',
        guidance:
          'The effort required to respond is significant with potentially extended service impact.',
        medicalExample:
          'Complex medical device replacement, extensive clinical workflow redesign, prolonged service outages, significant healthcare facility resources required',
      },
    ],
  },
  U: {
    general: {
      description:
        'Provider Urgency is a pass-through metric allowing vendors to provide supplemental severity ratings for vulnerability remediation urgency.',
      medicalDeviceContext:
        'Consider manufacturer recommendations, FDA alerts, clinical urgency, and patient safety priorities for medical device vulnerability remediation.',
      examples: [
        'Manufacturer security advisories',
        'FDA safety communications urgency levels',
        'Clinical priority assessments',
        'Patient safety risk classifications',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The Provider Urgency metric is not defined or is not applicable.',
        medicalExample:
          'Default supplemental scoring, no manufacturer urgency classification provided',
      },
      {
        value: 'Clear',
        guidance:
          'Informational only with no specific urgency for remediation.',
        medicalExample:
          'General medical device security awareness, non-critical informational updates, routine security notifications, educational advisories',
      },
      {
        value: 'Green',
        guidance:
          'Reduced urgency for remediation with standard timelines.',
        medicalExample:
          'Non-critical medical device updates, routine maintenance window patches, low-risk security improvements, standard clinical scheduling',
      },
      {
        value: 'Amber',
        guidance:
          'Moderate urgency requiring timely but not emergency response.',
        medicalExample:
          'Important medical device security updates, clinical workflow considerations, coordinated maintenance scheduling, elevated priority patches',
      },
      {
        value: 'Red',
        guidance:
          'Highest urgency requiring immediate attention and emergency response.',
        medicalExample:
          'Critical patient safety vulnerabilities, immediate medical device shutdown required, emergency clinical protocol activation, urgent FDA safety alerts',
      },
    ],
  },
  // CVSS v4.0 Environmental Metrics - Modified Base Metrics
  MAV: {
    general: {
      description:
        'Modified Attack Vector allows customization of the Attack Vector metric based on specific environmental conditions.',
      medicalDeviceContext:
        'Adjust attack vector assessment based on healthcare facility network architecture, medical device deployment, and clinical environment security controls.',
      examples: [
        'Healthcare network segmentation effects',
        'Medical device isolation measures',
        'Clinical environment access controls',
        'Hospital security architecture modifications',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Attack Vector value.',
        medicalExample:
          'Default environmental scoring, no specific network modifications in this healthcare facility',
      },
      {
        value: 'N',
        guidance: 'Network access is maintained or expanded in the target environment.',
        medicalExample:
          'Medical devices directly connected to internet, hospital network with external connectivity, telemedicine platform access',
      },
      {
        value: 'A',
        guidance: 'Adjacent network access is required in the target environment.',
        medicalExample:
          'Medical devices on isolated network segments, WiFi-enabled devices in clinical areas, Bluetooth medical sensors',
      },
      {
        value: 'L',
        guidance: 'Local access is required in the target environment.',
        medicalExample:
          'Medical devices requiring direct connection, bedside terminal access, local diagnostic equipment',
      },
      {
        value: 'P',
        guidance: 'Physical access is required in the target environment.',
        medicalExample:
          'Physically secured medical devices, devices in locked clinical areas, implantable devices requiring physical contact',
      },
    ],
  },
  MAC: {
    general: {
      description:
        'Modified Attack Complexity allows customization based on environmental security controls and deployment conditions.',
      medicalDeviceContext:
        'Adjust complexity assessment based on healthcare facility security measures, clinical workflow protections, and medical device hardening.',
      examples: [
        'Additional medical device authentication',
        'Clinical workflow security controls',
        'Healthcare facility access restrictions',
        'Medical device hardening measures',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Attack Complexity value.',
        medicalExample:
          'Default environmental scoring, no specific security modifications in this healthcare environment',
      },
      {
        value: 'L',
        guidance: 'Attack complexity remains low in the target environment.',
        medicalExample:
          'Standard medical device configurations, default healthcare settings, minimal additional security controls',
      },
      {
        value: 'H',
        guidance: 'Attack complexity is increased by environmental security controls.',
        medicalExample:
          'Enhanced medical device authentication, additional clinical access controls, specialized healthcare security measures',
      },
    ],
  },
  MAT: {
    general: {
      description:
        'Modified Attack Requirements allows customization based on environmental deployment conditions that affect attack prerequisites.',
      medicalDeviceContext:
        'Adjust attack requirements based on specific clinical workflows, medical device configurations, and healthcare operational conditions.',
      examples: [
        'Clinical workflow modifications',
        'Medical device operational modes',
        'Healthcare procedure requirements',
        'Patient care environment conditions',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Attack Requirements value.',
        medicalExample:
          'Default environmental scoring, no specific workflow modifications in this clinical environment',
      },
      {
        value: 'N',
        guidance: 'No additional attack requirements exist in the target environment.',
        medicalExample:
          'Standard clinical operations, typical medical device deployment, routine healthcare procedures',
      },
      {
        value: 'P',
        guidance: 'Additional attack requirements are present in the target environment.',
        medicalExample:
          'Specialized clinical procedures required, medical device maintenance modes, specific patient care protocols, enhanced healthcare workflows',
      },
    ],
  },
  MPR: {
    general: {
      description:
        'Modified Privileges Required allows customization based on environmental access controls and user privilege systems.',
      medicalDeviceContext:
        'Adjust privilege requirements based on healthcare facility access controls, clinical role assignments, and medical device user management.',
      examples: [
        'Clinical role-based access controls',
        'Medical device user authentication',
        'Healthcare facility privilege systems',
        'Patient care access restrictions',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Privileges Required value.',
        medicalExample:
          'Default environmental scoring, no specific privilege modifications in this healthcare facility',
      },
      {
        value: 'N',
        guidance: 'No privileges are required in the target environment.',
        medicalExample:
          'Open access medical systems, public healthcare interfaces, unauthenticated medical devices',
      },
      {
        value: 'L',
        guidance: 'Low-level privileges are required in the target environment.',
        medicalExample:
          'Basic clinical user accounts, standard patient access, limited medical device permissions',
      },
      {
        value: 'H',
        guidance: 'High-level privileges are required in the target environment.',
        medicalExample:
          'Administrative healthcare access, biomedical engineering privileges, critical system permissions, clinical supervisor rights',
      },
    ],
  },
  MUI: {
    general: {
      description:
        'Modified User Interaction allows customization based on environmental user behavior and interaction patterns.',
      medicalDeviceContext:
        'Adjust user interaction requirements based on clinical workflows, healthcare staff behavior, and patient interaction patterns.',
      examples: [
        'Clinical staff training levels',
        'Healthcare workflow automation',
        'Patient interaction requirements',
        'Medical device operation patterns',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original User Interaction value.',
        medicalExample:
          'Default environmental scoring, no specific interaction modifications in this clinical environment',
      },
      {
        value: 'N',
        guidance: 'No user interaction is required in the target environment.',
        medicalExample:
          'Automated medical processes, background healthcare services, unattended medical device operations',
      },
      {
        value: 'P',
        guidance: 'Passive user interaction is required in the target environment.',
        medicalExample:
          'Routine clinical operations, standard patient care procedures, normal medical device usage',
      },
      {
        value: 'A',
        guidance: 'Active user interaction is required in the target environment.',
        medicalExample:
          'Deliberate clinical staff actions, specific patient interactions, non-standard medical device procedures',
      },
    ],
  },
  MVC: {
    general: {
      description:
        'Modified Vulnerable System Confidentiality Impact allows customization based on environmental data sensitivity and protection measures.',
      medicalDeviceContext:
        'Adjust confidentiality impact based on specific patient data stored on the device, healthcare data classifications, and clinical information sensitivity.',
      examples: [
        'Patient data sensitivity levels',
        'Medical device data storage',
        'Clinical information classifications',
        'Healthcare privacy requirements',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Vulnerable System Confidentiality value.',
        medicalExample:
          'Default environmental scoring, no specific confidentiality modifications for this medical device',
      },
      {
        value: 'N',
        guidance: 'No confidentiality impact to the vulnerable system in this environment.',
        medicalExample:
          'Medical devices with no patient data, anonymized telemetry only, public clinical information',
      },
      {
        value: 'L',
        guidance: 'Low confidentiality impact to the vulnerable system in this environment.',
        medicalExample:
          'Limited patient identifiers, non-sensitive clinical data, device usage patterns',
      },
      {
        value: 'H',
        guidance: 'High confidentiality impact to the vulnerable system in this environment.',
        medicalExample:
          'Comprehensive patient medical records, sensitive diagnostic data, protected health information on device',
      },
    ],
  },
  MVI: {
    general: {
      description:
        'Modified Vulnerable System Integrity Impact allows customization based on environmental data integrity requirements and protection measures.',
      medicalDeviceContext:
        'Adjust integrity impact based on critical medical data on the device, clinical decision support requirements, and patient safety dependencies.',
      examples: [
        'Critical medical data integrity',
        'Clinical decision support accuracy',
        'Medical device calibration data',
        'Patient safety-critical parameters',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Vulnerable System Integrity value.',
        medicalExample:
          'Default environmental scoring, no specific integrity modifications for this medical device',
      },
      {
        value: 'N',
        guidance: 'No integrity impact to the vulnerable system in this environment.',
        medicalExample:
          'Read-only medical devices, non-modifiable device data, display-only clinical information',
      },
      {
        value: 'L',
        guidance: 'Low integrity impact to the vulnerable system in this environment.',
        medicalExample:
          'Non-critical device settings, minor configuration parameters, non-essential medical data',
      },
      {
        value: 'H',
        guidance: 'High integrity impact to the vulnerable system in this environment.',
        medicalExample:
          'Critical treatment parameters, life-support settings, surgical device controls, medication dosage data',
      },
    ],
  },
  MVA: {
    general: {
      description:
        'Modified Vulnerable System Availability Impact allows customization based on environmental availability requirements and redundancy measures.',
      medicalDeviceContext:
        'Adjust availability impact based on medical device criticality, patient care dependencies, emergency use requirements, and backup systems.',
      examples: [
        'Life-critical medical devices',
        'Emergency medical equipment',
        'Patient monitoring systems',
        'Backup medical device availability',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Vulnerable System Availability value.',
        medicalExample:
          'Default environmental scoring, no specific availability modifications for this medical device',
      },
      {
        value: 'N',
        guidance: 'No availability impact to the vulnerable system in this environment.',
        medicalExample:
          'Non-critical medical devices, redundant systems available, backup medical equipment present',
      },
      {
        value: 'L',
        guidance: 'Low availability impact to the vulnerable system in this environment.',
        medicalExample:
          'Non-essential medical devices, delayed medical procedures acceptable, routine clinical equipment',
      },
      {
        value: 'H',
        guidance: 'High availability impact to the vulnerable system in this environment.',
        medicalExample:
          'Life-support systems, emergency medical equipment, critical patient monitoring, no backup available',
      },
    ],
  },
  MSC: {
    general: {
      description:
        'Modified Subsequent System Confidentiality Impact allows customization based on environmental network architecture and data flow patterns.',
      medicalDeviceContext:
        'Adjust subsequent system confidentiality impact based on healthcare network connectivity, medical system integration, and data sharing patterns.',
      examples: [
        'Hospital network connectivity',
        'Medical system integration',
        'Healthcare data sharing',
        'Clinical network architecture',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Subsequent System Confidentiality value.',
        medicalExample:
          'Default environmental scoring, no specific network modifications in this healthcare environment',
      },
      {
        value: 'N',
        guidance: 'No confidentiality impact to subsequent systems in this environment.',
        medicalExample:
          'Isolated medical devices, air-gapped clinical networks, no connected healthcare systems',
      },
      {
        value: 'L',
        guidance: 'Low confidentiality impact to subsequent systems in this environment.',
        medicalExample:
          'Limited network connectivity, segmented healthcare systems, restricted data sharing',
      },
      {
        value: 'H',
        guidance: 'High confidentiality impact to subsequent systems in this environment.',
        medicalExample:
          'Extensive healthcare network access, integrated medical systems, widespread data connectivity',
      },
    ],
  },
  MSI: {
    general: {
      description:
        'Modified Subsequent System Integrity Impact allows customization based on environmental system interdependencies and data consistency requirements.',
      medicalDeviceContext:
        'Adjust subsequent system integrity impact based on medical system interdependencies, clinical data consistency requirements, and healthcare workflow integration.',
      examples: [
        'Medical system interdependencies',
        'Clinical data consistency',
        'Healthcare workflow integration',
        'Cross-system data integrity',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Subsequent System Integrity value.',
        medicalExample:
          'Default environmental scoring, no specific integration modifications in this healthcare environment',
      },
      {
        value: 'N',
        guidance: 'No integrity impact to subsequent systems in this environment.',
        medicalExample:
          'Standalone medical devices, isolated clinical systems, no data sharing dependencies',
      },
      {
        value: 'L',
        guidance: 'Low integrity impact to subsequent systems in this environment.',
        medicalExample:
          'Limited system integration, non-critical data sharing, isolated clinical workflows',
      },
      {
        value: 'H',
        guidance: 'High integrity impact to subsequent systems in this environment.',
        medicalExample:
          'Critical system interdependencies, essential data consistency requirements, integrated clinical workflows',
      },
    ],
  },
  MSA: {
    general: {
      description:
        'Modified Subsequent System Availability Impact allows customization based on environmental system dependencies and operational redundancy.',
      medicalDeviceContext:
        'Adjust subsequent system availability impact based on healthcare system dependencies, clinical operation redundancy, and medical service continuity requirements.',
      examples: [
        'Healthcare system dependencies',
        'Clinical operation redundancy',
        'Medical service continuity',
        'Emergency backup systems',
      ],
    },
    options: [
      {
        value: 'X',
        guidance: 'The environmental impact is not defined, use original Subsequent System Availability value.',
        medicalExample:
          'Default environmental scoring, no specific dependency modifications in this healthcare environment',
      },
      {
        value: 'N',
        guidance: 'No availability impact to subsequent systems in this environment.',
        medicalExample:
          'Independent medical devices, redundant healthcare systems, backup clinical operations available',
      },
      {
        value: 'L',
        guidance: 'Low availability impact to subsequent systems in this environment.',
        medicalExample:
          'Limited system dependencies, partial redundancy available, non-critical healthcare operations',
      },
      {
        value: 'H',
        guidance: 'High availability impact to subsequent systems in this environment.',
        medicalExample:
          'Critical system dependencies, no redundancy available, essential healthcare operations at risk',
      },
    ],
  },
};
