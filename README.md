# AI Cloud Security Lab — Training Data

Real-world security scenarios built for hands-on learning. Deploy tools, analyze threats, and build your portfolio — all AI-augmented.

## What's in here

This repo contains the datasets, artifacts, and scenario materials used across the [AI Cloud Security Lab](https://www.skool.com/cloud-security-lab) curriculum.

Everything is built around a single fictional engagement: **securing CloudVault Financial**, a mid-size wealth management firm with real security problems that need solving.

### CloudVault Financial

CloudVault Financial is a fictional wealth management firm (~200 employees, $2.1B AUM, AWS-primary) that just hired you as their security lead. Their environment has real issues buried in the data — misconfigured security groups, unauthorized access, privilege escalation, compliance gaps, and more.

Your job: find the problems, fix them, and build the security program — using AI at every step.

## Repo Structure

```
ai-csl-data/
├── cloudvault-financial/
│   ├── company-profile.md          # Client briefing — read this first
│   ├── cloudtrail-week1.json       # Week 1 CloudTrail logs (Course 1, 2)
│   ├── guardduty-findings.json     # 47 GuardDuty findings (Course 2)     [coming soon]
│   ├── soc2-compliance-tracker.csv # 200 SOC 2 controls (Course 2, 7)     [coming soon]
│   ├── incident-sequence.json      # Full attack chain data (Course 2, 5) [coming soon]
│   └── vendor-questionnaire.csv    # Vendor security review (Course 2)    [coming soon]
└── README.md
```

New datasets are added as courses are released. If you've added this as a submodule (see below), just pull the latest to get new data.

## How to use this

### If you're an AI Cloud Security Lab member

This repo is designed to plug into your **ContextOS workspace** as a submodule. If you followed the course setup, this is already in your workspace at `lab-data/`. When new data is added, update it:

```bash
cd your-contextOS-folder
git submodule update --remote lab-data
```

Or just ask Claude Code:

> "Pull the latest lab data from GitHub."

### If you found this on GitHub

The data is free to explore. Try loading `cloudvault-financial/cloudtrail-week1.json` into any AI tool and asking it to find the security issues. See what you find.

If you want the full experience — guided courses, hands-on labs (Wazuh, Shuffle, Metasploit), portfolio building, and a community of security practitioners learning to use AI — join us:

**[AI Cloud Security Lab on Skool](https://www.skool.com/cloud-security-lab)** — a hands-on community for cloud security professionals building with AI.

## What this is NOT

- This is **not real company data**. CloudVault Financial is entirely fictional.
- There are **no real credentials, keys, or secrets** in any file.
- The CloudTrail logs, GuardDuty findings, and compliance data are crafted training scenarios with realistic patterns.

## License

This training data is provided for educational use. You're free to use it for personal learning, training, and practice.
