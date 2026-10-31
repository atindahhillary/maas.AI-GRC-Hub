import type { BlueprintLayer } from './types'

// Prices are rough planning estimates in USD, not quotes. Check current vendor pricing.
export const BLUEPRINT: BlueprintLayer[] = [
  {
    id: 'identity-sso',
    title: 'Identity and SSO',
    outcome: 'Every account uses strong sign-in, and access can be removed in one place.',
    phase: 30,
    controls: ['IAM-01', 'IAM-02', 'IAM-03', 'IAM-04'],
    options: {
      minimal: {
        approach: 'Turn on the MFA already included in your email suite and adopt a password manager.',
        examples: ['Microsoft Entra security defaults', 'Google Workspace 2-Step Verification', 'Bitwarden', 'Keycloak', 'authentik'],
        monthlyCostUsd: '0 to 4 per user, estimate',
      },
      moderate: {
        approach: 'Single sign-on for key apps with conditional access rules based on device and location.',
        examples: ['Microsoft Entra ID P1', 'Google Cloud Identity Premium', 'JumpCloud', 'Okta Workforce Identity', '1Password Business'],
        monthlyCostUsd: '6 to 15 per user, estimate',
      },
      substantial: {
        approach: 'Risk-based access, automated joiner and leaver processes, phishing-resistant keys for admins and privileged access controls.',
        examples: ['Microsoft Entra ID P2', 'Okta Identity Governance', 'YubiKey', 'CyberArk', 'BeyondTrust'],
        monthlyCostUsd: '15 to 40 per user, estimate',
      },
    },
  },
  {
    id: 'email-security',
    title: 'Email security',
    outcome: 'Others cannot easily spoof your domain, and fewer phishing messages reach staff.',
    phase: 30,
    controls: ['NET-01', 'NET-02'],
    options: {
      minimal: {
        approach: 'Publish SPF, DKIM and DMARC, read the reports and use the filtering already included in your mail service.',
        examples: ['Exchange Online Protection', 'Gmail built-in protections', 'parsedmarc', 'Google Postmaster Tools'],
        monthlyCostUsd: '0 to 20 in total, estimate',
      },
      moderate: {
        approach: 'Add a paid filtering layer with link and attachment checks, and a hosted DMARC reporting service.',
        examples: ['Microsoft Defender for Office 365 Plan 1', 'Proofpoint Essentials', 'Mimecast', 'dmarcian', 'Valimail'],
        monthlyCostUsd: '2 to 6 per user, estimate',
      },
      substantial: {
        approach: 'Behavioural detection for account takeover and payment fraud, with automated removal of malicious mail.',
        examples: ['Microsoft Defender for Office 365 Plan 2', 'Abnormal AI', 'Proofpoint Email Protection', 'Mimecast'],
        monthlyCostUsd: '5 to 15 per user, estimate',
      },
    },
  },
  {
    id: 'backup',
    title: 'Backup and recovery',
    outcome: 'Key data can be restored after ransomware or error, and that has been proven by a test.',
    phase: 30,
    controls: ['RES-01', 'RES-02', 'RES-03'],
    options: {
      minimal: {
        approach: 'Encrypted scheduled backups to low-cost object storage with immutability turned on, plus a quarterly restore test.',
        examples: ['restic', 'BorgBackup', 'Veeam Backup & Replication Community Edition', 'Backblaze B2 with Object Lock', 'Amazon S3 Object Lock'],
        monthlyCostUsd: '5 to 50 in total, depends on storage, estimate',
      },
      moderate: {
        approach: 'Managed backup for endpoints, servers and SaaS data such as Microsoft 365 or Google Workspace.',
        examples: ['Acronis Cyber Protect', 'Veeam Data Cloud', 'Afi Backup', 'Backblaze Business Backup'],
        monthlyCostUsd: '3 to 8 per user, estimate',
      },
      substantial: {
        approach: 'Immutable enterprise backup with isolated recovery, automated restore testing and ransomware scanning.',
        examples: ['Rubrik', 'Cohesity', 'Veeam Data Platform', 'Commvault'],
        monthlyCostUsd: 'Quote based, often 8 to 25 per user, estimate',
      },
    },
  },
  {
    id: 'endpoint-protection',
    title: 'Endpoint protection',
    outcome: 'Every work device is encrypted, protected and able to be located or wiped.',
    phase: 60,
    controls: ['END-01', 'END-03', 'END-04'],
    options: {
      minimal: {
        approach: 'Use the built-in protection and encryption in the operating system, with a manual monthly check.',
        examples: ['Microsoft Defender Antivirus', 'BitLocker', 'FileVault', 'Wazuh agent', 'ClamAV'],
        monthlyCostUsd: '0 to 3 per device, estimate',
      },
      moderate: {
        approach: 'Central endpoint detection and device management with enforced encryption and remote wipe.',
        examples: ['Microsoft Defender for Business', 'Microsoft Intune', 'ESET PROTECT', 'Bitdefender GravityZone', 'Sophos Intercept X'],
        monthlyCostUsd: '3 to 12 per user, estimate',
      },
      substantial: {
        approach: 'Full endpoint detection and response with a managed service watching alerts around the clock.',
        examples: ['CrowdStrike Falcon', 'SentinelOne Singularity', 'Microsoft Defender for Endpoint Plan 2', 'Huntress Managed EDR'],
        monthlyCostUsd: '8 to 30 per endpoint, estimate',
      },
    },
  },
  {
    id: 'patching-inventory',
    title: 'Patching and asset inventory',
    outcome: 'You know what you own, and critical updates are applied within agreed times.',
    phase: 60,
    controls: ['GOV-04', 'END-02', 'END-05'],
    options: {
      minimal: {
        approach: 'A simple asset register, automatic updates turned on and a monthly vulnerability scan.',
        examples: ['Snipe-IT', 'GLPI', 'Windows Update for Business', 'unattended-upgrades', 'Greenbone Community Edition'],
        monthlyCostUsd: '0 to 50 in total, estimate',
      },
      moderate: {
        approach: 'Central patch management across operating systems and third-party apps, with compliance reports.',
        examples: ['Action1', 'NinjaOne', 'ManageEngine Patch Manager Plus', 'Microsoft Intune', 'Nessus Professional'],
        monthlyCostUsd: '2 to 6 per device, estimate',
      },
      substantial: {
        approach: 'Continuous vulnerability management ranked by exploit risk, including cloud and external attack surface.',
        examples: ['Tenable Vulnerability Management', 'Qualys VMDR', 'Rapid7 InsightVM', 'Windows Autopatch'],
        monthlyCostUsd: 'Quote based, often 3 to 10 per asset, estimate',
      },
    },
  },
  {
    id: 'ai-gateway',
    title: 'AI gateway and guardrails',
    outcome: 'AI use goes through approved routes, with sensitive data filtered, actions limited and activity logged.',
    phase: 60,
    controls: ['AI-01', 'AI-02', 'AI-03', 'AI-05', 'AI-06', 'AI-07', 'AI-08', 'AI-09'],
    appliesIf: p => p.usesAI || p.buildsAI,
    options: {
      minimal: {
        approach: 'One approved business-grade tool with training turned off. If you build AI, add a self-hosted gateway with redaction and logging.',
        examples: ['LiteLLM', 'Microsoft Presidio', 'NeMo Guardrails', 'Langfuse', 'Ollama'],
        monthlyCostUsd: '0 to 50 in total for hosting, model usage extra, estimate',
      },
      moderate: {
        approach: 'Business AI seats with admin controls, plus a managed gateway for routing, logging and spend limits.',
        examples: ['ChatGPT Business', 'Claude Team', 'Microsoft 365 Copilot', 'Gemini for Google Workspace', 'Cloudflare AI Gateway', 'Portkey'],
        monthlyCostUsd: '20 to 35 per user for AI seats, model usage extra, estimate',
      },
      substantial: {
        approach: 'Enterprise AI plans with single sign-on, audit logs, data loss prevention and managed content and injection filtering.',
        examples: ['ChatGPT Enterprise', 'Claude Enterprise', 'Amazon Bedrock Guardrails', 'Azure AI Content Safety', 'Google Cloud Model Armor', 'Microsoft Purview'],
        monthlyCostUsd: 'Quote based, often 30 to 60 per user plus usage, estimate',
      },
    },
  },
  {
    id: 'awareness-training',
    title: 'Awareness training',
    outcome: 'Staff recognise phishing and misuse of AI, and report problems early.',
    phase: 60,
    controls: ['PPL-01', 'PPL-02', 'AI-13'],
    options: {
      minimal: {
        approach: 'A short annual session using free material, plus a simple phishing exercise you run yourself.',
        examples: ['NCSC Top Tips for Staff', 'Gophish', 'Google Phishing Quiz', 'Elements of AI'],
        monthlyCostUsd: '0 to 20 in total, estimate',
      },
      moderate: {
        approach: 'A hosted training platform with phishing simulation and reports on completion.',
        examples: ['KnowBe4', 'Hoxhunt', 'Huntress Managed Security Awareness Training', 'Microsoft Defender Attack Simulation Training'],
        monthlyCostUsd: '1 to 4 per user, estimate',
      },
      substantial: {
        approach: 'Role-based training for finance, admins, developers and leaders, with measured behaviour change and executive exercises.',
        examples: ['SANS Security Awareness', 'Proofpoint Security Awareness', 'KnowBe4', 'Hoxhunt'],
        monthlyCostUsd: '3 to 8 per user, estimate',
      },
    },
  },
  {
    id: 'network-web-protection',
    title: 'Network and web protection',
    outcome: 'Websites and remote access are protected, and only what must be public is exposed.',
    phase: 90,
    controls: ['NET-03', 'NET-04', 'NET-05', 'DAT-04'],
    options: {
      minimal: {
        approach: 'Free CDN and basic firewall in front of websites, free certificates, and private access to admin tools.',
        examples: ['Cloudflare Free', "Let's Encrypt", 'WireGuard', 'Tailscale', 'OPNsense'],
        monthlyCostUsd: '0 to 20 in total, estimate',
      },
      moderate: {
        approach: 'Managed web application firewall, zero trust access in place of VPN and a business firewall at the office.',
        examples: ['Cloudflare Pro', 'Cloudflare Zero Trust', 'AWS WAF', 'Tailscale', 'Fortinet FortiGate'],
        monthlyCostUsd: '25 to 300 per site, plus 0 to 8 per user for access, estimate',
      },
      substantial: {
        approach: 'Secure access service edge with inspection of user traffic, advanced bot and DDoS protection and network segmentation.',
        examples: ['Zscaler', 'Palo Alto Networks Prisma Access', 'Cloudflare Enterprise', 'Netskope'],
        monthlyCostUsd: 'Quote based, often 10 to 30 per user, estimate',
      },
    },
  },
  {
    id: 'data-protection',
    title: 'Data protection',
    outcome: 'Sensitive data is known, labelled, encrypted and harder to leak.',
    phase: 90,
    controls: ['DAT-01', 'DAT-04', 'DAT-10', 'AI-03'],
    options: {
      minimal: {
        approach: 'A short data map, three classification labels, encryption at rest and basic sharing restrictions in your suite.',
        examples: ['Microsoft 365 sharing settings', 'Google Drive sharing settings', 'Cryptomator', 'VeraCrypt', 'Gitleaks'],
        monthlyCostUsd: '0 to 20 in total, estimate',
      },
      moderate: {
        approach: 'Sensitivity labels and data loss prevention for email and files.',
        examples: ['Microsoft Purview Information Protection', 'Google Workspace DLP', 'Nightfall AI'],
        monthlyCostUsd: '3 to 12 per user, estimate',
      },
      substantial: {
        approach: 'Automated discovery and classification across cloud stores, with insider risk monitoring.',
        examples: ['Microsoft Purview', 'Varonis', 'Netskope One DLP', 'Forcepoint DLP'],
        monthlyCostUsd: 'Quote based, often 10 to 30 per user, estimate',
      },
    },
  },
  {
    id: 'secure-development',
    title: 'Secure development',
    outcome: 'Code and third-party packages are checked before release, and changes are reviewed.',
    phase: 90,
    controls: ['APP-01', 'APP-02', 'APP-03', 'APP-06', 'AI-10'],
    options: {
      minimal: {
        approach: 'Branch protection, dependency alerts and free scanners in the build pipeline. If you do not write code, apply this to your website and your developers.',
        examples: ['GitHub Dependabot', 'Semgrep Community Edition', 'Gitleaks', 'Trivy', 'ZAP'],
        monthlyCostUsd: '0 to 50 in total, estimate',
      },
      moderate: {
        approach: 'Commercial code, dependency and secret scanning with pull request checks.',
        examples: ['Snyk', 'GitHub Advanced Security', 'SonarQube Cloud', 'Semgrep AppSec Platform'],
        monthlyCostUsd: '20 to 60 per developer, estimate',
      },
      substantial: {
        approach: 'An application security programme with threat modelling, a yearly independent penetration test and a vulnerability disclosure route.',
        examples: ['Checkmarx One', 'Veracode', 'Snyk Enterprise', 'HackerOne'],
        monthlyCostUsd: 'Quote based, plan 1,000 or more in total, estimate',
      },
    },
  },
  {
    id: 'logging-detection',
    title: 'Logging and detection',
    outcome: 'Important events are kept, and someone is alerted when something looks wrong.',
    phase: 180,
    controls: ['INC-04', 'CLD-04', 'AI-09'],
    options: {
      minimal: {
        approach: 'Turn on audit logs in your email and cloud services, set retention and add a few alerts. Run a self-hosted stack if you have the skills.',
        examples: ['Microsoft Purview Audit', 'Google Workspace audit logs', 'AWS CloudTrail', 'Wazuh', 'Grafana Loki'],
        monthlyCostUsd: '0 to 100 in total for hosting, estimate',
      },
      moderate: {
        approach: 'A cloud SIEM or a managed log service with tuned alerts for sign-in and admin activity.',
        examples: ['Microsoft Sentinel', 'Elastic Security', 'Grafana Cloud', 'Huntress Managed SIEM'],
        monthlyCostUsd: '200 to 1,000 in total, based on log volume, estimate',
      },
      substantial: {
        approach: 'A 24 hour managed detection and response service covering endpoints, identity and cloud.',
        examples: ['Arctic Wolf', 'Sophos MDR', 'Expel', 'Splunk Enterprise Security'],
        monthlyCostUsd: 'Quote based, often 10 to 40 per user, estimate',
      },
    },
  },
  {
    id: 'vendor-risk',
    title: 'Vendor risk',
    outcome: 'Suppliers who hold your data are known, assessed and contractually bound.',
    phase: 180,
    controls: ['VEN-01', 'VEN-02', 'VEN-03', 'AI-05'],
    options: {
      minimal: {
        approach: 'A supplier register in a spreadsheet, a short questionnaire for high-risk suppliers and a contract clause checklist.',
        examples: ['Excel or Google Sheets', 'CSA CAIQ', 'VSA Core questionnaire', 'Mozilla HTTP Observatory'],
        monthlyCostUsd: '0 in tooling, staff time only, estimate',
      },
      moderate: {
        approach: 'A compliance platform with supplier reviews, or external rating of high-risk suppliers.',
        examples: ['Vanta', 'Drata', 'Secureframe', 'UpGuard'],
        monthlyCostUsd: '300 to 1,500 in total, estimate',
      },
      substantial: {
        approach: 'A dedicated third-party risk platform with continuous monitoring and workflow.',
        examples: ['OneTrust Third-Party Risk Management', 'ProcessUnity', 'SecurityScorecard', 'Bitsight'],
        monthlyCostUsd: 'Quote based, often 1,500 or more in total, estimate',
      },
    },
  },
]
