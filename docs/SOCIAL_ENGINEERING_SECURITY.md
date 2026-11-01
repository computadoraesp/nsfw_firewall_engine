# Social Engineering Security Policy

This document provides guidelines and best practices to protect the NSFW Firewall Engine from social engineering attacks.

## What is Social Engineering?

Social engineering is the manipulation of people to obtain confidential information or access to systems. Unlike technical attacks, social engineering targets human psychology.

## Common Social Engineering Attacks

### 1. Phishing
Emails or messages that appear legitimate but are designed to steal credentials or install malware.

**Example:** An email claiming to be from Cloudflare support asking for API keys.

### 2. Vishing (Voice Phishing)
Phone calls from attackers pretending to be legitimate support personnel.

**Example:** A call claiming to be from the security team requesting password reset.

### 3. Smishing (SMS Phishing)
Text messages containing malicious links or requests for sensitive information.

### 4. Business Email Compromise (BEC)
Compromised legitimate business email accounts used to request fraudulent payments or data.

### 5. Pretexting
Creating a fabricated scenario to obtain information.

**Example:** An attacker claiming to be a vendor needing access to test a new integration.

### 6. Baiting
Offering something enticing to trick victims (e.g., infected USB drive left in parking lot).

## Protection Policies

### Password and Credential Management

#### ✅ Required Practices

1. **Never share credentials** via email, chat, or phone
2. **Use unique passwords** for each system
3. **Enable MFA** wherever possible
4. **Rotate secrets** regularly (API keys, TLS certificates)
5. **Store secrets securely** (environment variables, secret managers)
6. **Never commit secrets** to version control

#### ❌ Prohibited Practices

1. Sharing credentials with colleagues
2. Writing passwords on sticky notes
3. Storing passwords in plain text files
4. Reusing passwords across systems
5. Sharing API keys in support tickets

### Incident Response Procedures

#### If You Suspect a Phishing Attempt

1. **Do not click** any links or download attachments
2. **Do not reply** to the message
3. **Report** to security team immediately
4. **Forward** the suspicious email to security@yourdomain.com
5. **Delete** the message after reporting

#### If You've Accidentally Shared Credentials

1. **Immediately rotate** the compromised credentials
2. **Report** the incident to security team
3. **Monitor** logs for suspicious activity
4. **Notify** affected stakeholders

### Access Control

#### Principle of Least Privilege

- Grant minimum access necessary for role
- Review access rights quarterly
- Revoke access immediately upon role change
- Use service accounts with limited permissions

#### Vendor and Third-Party Access

1. **Verify identity** before granting access
2. **Use temporary credentials** with expiration
3. **Monitor activity** of third-party accounts
4. **Terminate access** immediately after work completion
5. **Document** all third-party access

### Communication Security

#### Secure Communication Channels

- Use encrypted channels (Signal, encrypted email)
- Never share secrets over unencrypted channels
- Verify recipient identity before sending sensitive data
- Use official support channels for vendor communication

#### Verification Procedures

**Before sharing sensitive information:**

1. Verify the request came through official channels
2. Confirm with the requester through a separate channel
3. Check for unusual urgency or pressure tactics
4. Verify the request aligns with normal procedures

**Example verification:**
```
Attacker: "Please send me the API key immediately via email for emergency fix."
You: "I'll call you at your official number to verify."
Attacker: "No time for that, just send it!"
You: STOP - This is a red flag. Report to security.
```

## Training Requirements

### All Operators Must Complete

1. **Security Awareness Training** (annual)
   - Phishing recognition
   - Password security
   - Incident reporting

2. **Product-Specific Training** (onboarding)
   - NSFW Firewall Engine security features
   - Secret management procedures
   - Operational security best practices

3. **Simulation Exercises** (quarterly)
   - Phishing simulations
   - Social engineering scenarios
   - Incident response drills

### Security Team Must Complete

1. **Advanced Threat Training** (annual)
   - Advanced social engineering techniques
   - Threat intelligence analysis
   - Incident investigation

2. **Vendor Security Training** (as needed)
   - Third-party risk assessment
   - Supply chain security

## Operational Security (OpSec)

### What Can Be Shared Publicly

✅ **Safe to share:**
- System architecture (high-level)
- Security posture (hardening percentage)
- Public endpoints (after proper hardening)
- Documentation (without secrets)

### What Must Be Kept Confidential

❌ **Never share:**
- API keys or tokens
- Secret salts/peppers
- TLS private keys
- Internal IP addresses
- Unreleased security advisories
- Specific configuration details

### Public Communication Guidelines

When discussing security publicly:

1. **Focus on posture**, not specific defenses
2. **Avoid revealing** specific security measures
3. **Discuss** what was fixed, not how to exploit
4. **Coordinate** with security team before public disclosure

## Incident Response Checklist

### Pre-Incident Preparation

- [ ] Document all credentials and their locations
- [ ] Establish communication channels
- [ ] Define incident response team
- [ ] Create runbooks for common scenarios
- [ ] Set up monitoring and alerting

### During Incident

1. **Contain**
   - [ ] Isolate affected systems
   - [ ] Revoke compromised credentials
   - [ ] Disable suspicious accounts

2. **Investigate**
   - [ ] Preserve logs and evidence
   - [ ] Identify attack vector
   - [ ] Determine scope of compromise

3. **Eradicate**
   - [ ] Remove attacker access
   - [ ] Patch vulnerabilities
   - [ ] Update defenses

4. **Recover**
   - [ ] Restore from clean backups
   - [ ] Rotate all secrets
   - [ ] Monitor for recurrence

### Post-Incident

- [ ] Conduct post-mortem
- [ ] Document lessons learned
- [ ] Update procedures
- [ ] Provide training to affected personnel
- [ ] Report to stakeholders (if required)

## Signs of Social Engineering

### Red Flags

⚠️ **Urgency** - "Immediate action required"
⚠️ **Pressure** - Threats of consequences for non-compliance
⚠️ **Unusual requests** - Requesting credentials via email
⚠️ **Generic greetings** - "Dear Customer" instead of your name
⚠️ **Poor grammar/spelling** - Professional communication should be clean
⚠️ **Unusual sender** - Email from unexpected domain
⚠️ **Request for secrecy** - "Don't tell anyone about this"
⚠️ **Too good to be true** - Unexpected prizes or offers

### Verification Checklist

Before sharing sensitive information or taking action:

- [ ] Did the request come through official channels?
- [ ] Is the sender known and verified?
- [ ] Is the request normal for this context?
- [ ] Is there unusual urgency or pressure?
- [ ] Can I verify through a separate channel?
- [ ] Does the request align with policies?

## Resources

### Internal
- Security team: security@yourdomain.com
- Incident response: incident@yourdomain.com
- Documentation: docs/SECURITY.md

### External
- Report phishing: https://www.phishingreport.org/
- Security awareness: https://csrc.nist.gov/
- Social engineering training: https://www.sans.org/

## Policy Enforcement

### Violations

Intentional or negligent violations of this policy may result in:
- Mandatory retraining
- Access restrictions
- Disciplinary action
- Termination (for severe violations)

### Reporting

Security violations or suspicious activity should be reported to:
- Immediate supervisor
- Security team
- Anonymous hotline (if available)

**Retaliation against reporters is prohibited.**

## Review Schedule

This policy will be reviewed and updated:
- **Annually** - Full review
- **After incidents** - Update based on lessons learned
- **When new threats emerge** - Rapid update

---

**Document Version:** 1.0
**Last Updated:** 2026-11-01
**Next Review:** 2027-11-01
