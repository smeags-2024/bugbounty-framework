# Bug Bounty Testing Environment - Copilot Instructions

This repository contains prompt templates and documentation for setting up professional bug bounty testing environments on Kali Linux VMs.

## Repository Purpose

This is a **prompt library and documentation repository** for bug bounty hunters, not an active testing environment. It contains:
- Comprehensive prompt templates for AI assistants to set up penetration testing environments
- Professional methodology documentation covering OWASP, PTES, and bug bounty best practices
- Vulnerability testing checklists and reporting templates

## Key Conventions

### Prompts Location
All AI assistant prompts are stored in `.github/prompts/` with the naming pattern:
```
<action>-<description>.prompt.md
```

Example: `plan-bugBountyTestingEnvironment.prompt.md`

### Prompt Template Structure

When creating or modifying prompts in this repository:

1. **Section Organization**
   - Start with clear purpose statement and scope information placeholder
   - Include "Your Expert Role & Comprehensive Capabilities" section covering methodology
   - "Tool Arsenal Mastery" section listing reconnaissance, scanning, and exploitation tools
   - "Complete Implementation" section with directory structures and automation scripts
   - "Core Documentation Files" section specifying deliverable structure
   - "Safety & Ethics Framework" with pre-action verification and stop conditions
   - "Output Requirements" with explicit formatting expectations

2. **Scope Information Placeholder**
   - Always include `[PASTE COMPLETE SCOPE FROM HACKERONE/BUGCROWD INCLUDING:]` section
   - List what information should be pasted (program name, in-scope assets, out-of-scope, prohibited actions, severity levels, etc.)

3. **Vulnerability Coverage**
   - List specific vulnerability types with sub-techniques rather than generic categories
   - Example: "SQL Injection" should expand to "Union-based, Boolean-blind, Time-based, Error-based, Stacked queries"
   - Include bypass techniques and evasion methods for each vulnerability class

4. **Tool References**
   - Group tools by category (Reconnaissance, Scanning, Exploitation, etc.)
   - Include both tool names AND their specific use cases
   - Reference relevant Burp Suite extensions in manual testing sections

5. **MCP Integration**
   - Include "You Will Execute (via MCP)" sections with actual command examples
   - Show proper tool chaining with shell operators (`&&`, `|`, `>`)
   - Include rate limiting and timeout configurations

6. **Deliverables**
   - Explicitly list all files that should be created (scope.md, skills.md, checklist.md, findings.md, recon.md, workflow.md)
   - Specify the structure and required sections for each file
   - Include "Deliverables Checklist" at the end

7. **Output Quality Controls**
   - Always include "Do NOT truncate" instructions to prevent incomplete generations
   - Specify "FULL COMPLETE CONTENT HERE - NOT TRUNCATED" in code block examples
   - Request professional formatting and actionable content

### Professional Terminology

Use industry-standard security terminology:
- "IDOR" not "Insecure Direct Object Reference"
- "SSRF" not "Server-Side Request Forgery"
- "XSS" with subtypes (Reflected, Stored, DOM-based)
- Reference OWASP Top 10, PTES, WAHH
- Use CWE and CVSS standards

### Vulnerability Testing Methodology

Follow this phase structure in any methodology documentation:
1. Information Gathering (Passive OSINT, Active Recon)
2. Automated Vulnerability Assessment
3. Authentication & Authorization Testing
4. Injection Vulnerabilities
5. Server-Side Vulnerabilities
6. Client-Side Vulnerabilities
7. API Security
8. Business Logic Flaws
9. Mobile Security (if applicable)
10. Reporting & Documentation

### Safety and Ethics Framework

All prompts MUST include:
- Pre-action verification checklist (scope, rate limits, test accounts)
- Stop conditions where AI must alert human
- Responsible disclosure guidelines
- Data protection requirements (no production user data, PII sanitization)

### Documentation File Patterns

Standard files created by prompts for actual testing environments:
- `scope.md` - Program details, in/out-of-scope, rules
- `skills.md` - Complete testing methodology
- `checklist.md` - Phase-by-phase testing checklist
- `findings.md` - Vulnerability documentation template
- `recon.md` - Asset discovery tracking
- `workflow.md` - Daily routine and AI collaboration model
- `setup.sh` - Tool installation automation

## Repository Architecture

```
.github/
  prompts/           # AI assistant prompt templates
    *.prompt.md      # Individual prompt files
  copilot-instructions.md  # This file
plan.md             # Working notes/planning (not committed to git)
```

## Creating New Prompts

When adding new prompt templates:

1. **Filename**: Use descriptive action-noun format: `<verb>-<objective>.prompt.md`
2. **Character limit**: Keep under 25,000 characters for optimal AI model consumption
3. **Completeness**: List specific techniques to trigger comprehensive AI responses
4. **Examples**: Include concrete command examples, not just placeholders
5. **Customization points**: Clearly mark where program-specific info should be inserted with `[PLACEHOLDER_NAME]`

## Working with AI Assistants

This repository is designed to work WITH AI assistants (Claude, GitHub Copilot, ChatGPT, etc.):

### What AI Should Do
- Parse scope information and customize templates
- Execute reconnaissance commands via MCP
- Generate automation scripts
- Create comprehensive methodology documentation
- Draft vulnerability reports

### What Humans Should Do
- Provide program scope details
- Make final scope interpretation decisions
- Approve high-risk testing actions
- Review reports before submission
- Perform complex manual exploitation

### Collaboration Model
Prompts should establish a clear division of labor where AI handles repetitive tasks (scanning, parsing, documentation) while humans focus on creative exploitation and decision-making.

## Notes on Tool References

When referencing tools:
- Prefer Go-based tools for speed (subfinder, httpx, nuclei, ffuf)
- Always include update/installation commands
- Specify relevant tool flags and options
- Include wordlist locations (~/wordlists/SecLists/...)
- Reference nuclei template categories (exposures/, cves/, etc.)

## Ethics and Legal Compliance

All prompts must emphasize:
- Testing only explicitly in-scope assets
- Respecting rate limits (default 10 req/sec)
- Using test accounts only
- No DoS or destructive testing
- Immediate reporting of critical vulnerabilities
- Coordinated disclosure practices
- Safe harbor compliance
