# Vendor Security Questionnaire — WazuhCloud Inc.

> CloudVault Financial is evaluating WazuhCloud Inc. as a managed SIEM provider. Below are CloudVault's security questions and WazuhCloud's responses.
> Your job: review these responses and assess whether this vendor meets CloudVault's security requirements.

---

## Company Information

**Vendor:** WazuhCloud Inc.
**Service:** Managed Wazuh SIEM-as-a-Service
**Data processed:** Security logs, endpoint telemetry, network flow data
**Deployment:** Multi-tenant SaaS (AWS us-east-1 and eu-west-1)

---

## Questions and Vendor Responses

### Data Security

**Q1. How is customer data encrypted at rest?**
A: All data is encrypted at rest using AES-256 encryption via AWS S3 server-side encryption.

**Q2. How is customer data encrypted in transit?**
A: All data in transit is encrypted using TLS 1.2 or higher.

**Q3. Is customer data segregated from other customers' data?**
A: Yes, customer data is logically separated using unique tenant identifiers and access controls.

**Q4. Where is customer data stored geographically?**
A: Customer data is stored in AWS us-east-1 (Virginia) by default. EU customers can request eu-west-1 (Ireland).

**Q5. How long is customer data retained?**
A: Data is retained for 90 days by default. Customers can configure retention up to 365 days at additional cost.

**Q6. What happens to customer data upon contract termination?**
A: Customer data is deleted within 30 days of contract termination. Customers can request a data export before termination.

**Q7. Can customer data be accessed by vendor employees?**
A: Access to customer data is restricted to authorized support personnel on a need-to-know basis. All access is logged.

### Access Control

**Q8. How do you manage user authentication?**
A: We support SSO via SAML 2.0 and OIDC. Username/password authentication is also available.

**Q9. Is multi-factor authentication supported?**
A: MFA is available for all user accounts. It is not required by default but can be enforced by customer administrators.

**Q10. How do you manage privileged access internally?**
A: We follow the principle of least privilege. Administrative access requires MFA and is reviewed quarterly.

**Q11. How do you manage service accounts and API keys?**
A: API keys are generated per customer and can be rotated by the customer at any time. Service accounts use short-lived tokens.

**Q12. Do you perform regular access reviews?**
A: We conduct quarterly access reviews for all internal staff. Results are documented and available upon request.

### Infrastructure Security

**Q13. What cloud provider do you use?**
A: AWS. We leverage multiple availability zones for redundancy.

**Q14. How do you manage vulnerabilities in your infrastructure?**
A: We run weekly vulnerability scans and patch critical vulnerabilities within 72 hours. Non-critical patches are applied within 30 days.

**Q15. Do you use a WAF or DDoS protection?**
A: Yes, AWS WAF and AWS Shield Standard are deployed on all customer-facing endpoints.

**Q16. How do you secure your container infrastructure?**
A: We follow industry best practices for container security, including image scanning and runtime protection.

**Q17. Do you have a network segmentation strategy?**
A: Yes, our environment is segmented using VPCs, security groups, and network ACLs.

### Compliance

**Q18. Do you have a SOC 2 Type II report?**
A: We are currently pursuing SOC 2 Type I certification. Type II is expected by Q4 2026.

**Q19. Are you compliant with GDPR?**
A: Yes, we comply with GDPR requirements and have a Data Processing Agreement (DPA) available.

**Q20. Do you have a HIPAA BAA available?**
A: Not at this time. HIPAA compliance is on our 2027 roadmap.

**Q21. Have you completed a penetration test in the last 12 months?**
A: Yes, we completed a third-party penetration test in January 2026. The summary report is available under NDA.

**Q22. Do you have cyber insurance?**
A: Yes, we maintain cyber liability insurance with coverage up to $5M.

### Incident Response

**Q23. Do you have a documented incident response plan?**
A: Yes, our IR plan is based on the NIST framework and is tested annually.

**Q24. How quickly do you notify customers of a security incident?**
A: We notify affected customers within 72 hours of confirming a security incident.

**Q25. Have you experienced a data breach in the last 3 years?**
A: We have not experienced a data breach affecting customer data.

### Business Continuity

**Q26. What is your guaranteed uptime SLA?**
A: We guarantee 99.9% uptime, measured monthly.

**Q27. What is your RTO and RPO?**
A: RTO is 4 hours, RPO is 1 hour for all customer data.

**Q28. Do you have a disaster recovery plan?**
A: Yes, we maintain a DR plan with failover to a secondary AWS region. DR tests are conducted annually.

### Third-Party Risk

**Q29. Do you use any subprocessors?**
A: Yes, we use AWS for infrastructure, Datadog for monitoring, and PagerDuty for alerting.

**Q30. How do you assess the security of your subprocessors?**
A: We review subprocessor SOC 2 reports annually and maintain contracts requiring security standards compliance.

### Application Security

**Q31. Do you perform regular code reviews?**
A: All code changes go through peer review and automated SAST scanning before deployment.

**Q32. Do you have a secure software development lifecycle (SSDLC)?**
A: We follow an SSDLC based on OWASP guidelines, including threat modeling for new features.

**Q33. How often do you release updates?**
A: We deploy updates bi-weekly using a blue-green deployment strategy. Emergency patches can be deployed within 4 hours.

### Monitoring and Logging

**Q34. Do you monitor your own infrastructure for security events?**
A: Yes, we use our own Wazuh deployment to monitor our infrastructure. We also use AWS GuardDuty and CloudTrail.

**Q35. How long do you retain security logs?**
A: Internal security logs are retained for 365 days. CloudTrail logs are retained indefinitely in S3 Glacier.

**Q36. Can customers access audit logs for their own tenant?**
A: Yes, customers can access their tenant audit logs via the API or dashboard.

### Employee Security

**Q37. Do you perform background checks on employees?**
A: Yes, all employees undergo background checks before hiring.

**Q38. Do you provide security awareness training?**
A: Yes, all employees complete annual security awareness training and quarterly phishing simulations.

**Q39. How many employees have access to production systems?**
A: Approximately 8 employees have production access, all with MFA and just-in-time access provisioning.

### Data Privacy

**Q40. Do you have a privacy policy?**
A: Yes, our privacy policy is publicly available on our website.

**Q41. Do you process data in accordance with customer instructions only?**
A: Yes, we process data only as instructed by the customer and as defined in our DPA.

**Q42. Can customers request deletion of specific data?**
A: Yes, customers can submit deletion requests through our API or support portal. Deletion is completed within 14 business days.

### Change Management

**Q43. How do you manage changes to production?**
A: All changes follow our change management process including review, testing, approval, and rollback procedures.

**Q44. Do you maintain a change log?**
A: Yes, all production changes are logged and auditable.

### API Security

**Q45. How do you secure your API endpoints?**
A: APIs use OAuth 2.0 authentication, rate limiting, and input validation. All endpoints are documented in our API reference.

**Q46. Do you support IP allowlisting for API access?**
A: Yes, customers can configure IP allowlists for API access.

### Miscellaneous

**Q47. What is your average customer support response time?**
A: Standard support: 8 business hours. Priority support: 2 hours. Critical incidents: 30 minutes.

**Q48. Do you offer a dedicated customer success manager?**
A: For Enterprise plans ($10K+/year), yes. For Standard plans, support is ticket-based.

**Q49. Can we conduct our own security assessment of your service?**
A: We allow customer security assessments under our responsible testing policy. Please contact security@wazuhcloud.com to coordinate.

**Q50. Is your service FedRAMP authorized?**
A: Not at this time. We are evaluating FedRAMP authorization for 2027.
