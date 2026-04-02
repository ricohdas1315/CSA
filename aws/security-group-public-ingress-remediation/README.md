# AWS Security Group Public Ingress Auto-Remediation

This project implements an AWS event-driven auto-remediation control that detects and removes unauthorized public inbound Security Group rules. The solution uses CloudTrail, EventBridge, Lambda, IAM, and Python to automatically remediate inbound rules that expose a Security Group to the internet through `0.0.0.0/0` or `::/0`, unless the Security Group is explicitly tagged as an approved exception.

## Objective

Prevent unauthorized public exposure of AWS Security Groups by automatically removing inbound rules that allow internet-wide access.

## Policy Logic

The Lambda remediates when all of the following are true:

- the rule is inbound
- the source contains `0.0.0.0/0` or `::/0`
- the Security Group is not tagged `AllowPublicIngress=true`

The Lambda does not remediate when the Security Group has the exception tag:

- `AllowPublicIngress=true`

## Architecture Flow

1. A user adds or modifies a Security Group inbound rule.
2. CloudTrail records the EC2 API activity.
3. EventBridge matches the relevant event.
4. EventBridge invokes the Lambda function.
5. Lambda extracts the Security Group ID from the event.
6. Lambda retrieves the Security Group and checks for the exception tag.
7. Lambda removes any unauthorized public inbound rules.
8. Lambda logs the remediation result to CloudWatch.

## Event Coverage

This project currently supports the following API events:

- `AuthorizeSecurityGroupIngress`
- `ModifySecurityGroupRules`

## AWS Services Used

- AWS Lambda
- Amazon EventBridge
- AWS CloudTrail
- Amazon EC2 Security Groups
- AWS Identity and Access Management (IAM)
- Amazon CloudWatch Logs

## Files

- `lambda_function.py` - Lambda logic for parsing events, checking Security Groups, and revoking public ingress
- `event-sample.json` - sample test event for manual testing
- `notes.md` - build notes, testing notes, and proof-of-concept results

## Proof of Concept Results

The following paths were successfully tested:

- manual invocation using a provided Security Group ID
- automatic remediation for newly added public inbound rules
- automatic remediation for modified inbound rules changed to `0.0.0.0/0`
- exception handling for Security Groups tagged `AllowPublicIngress=true`

## Security Considerations

- The Lambda execution role was granted permissions to describe Security Groups and revoke inbound rules.
- The automation only removes public inbound exposure and does not modify exception-tagged Security Groups.
- CloudTrail was configured for management events only for this lab.
- S3 lifecycle expiration was configured to reduce long-term log retention costs.

## Future Enhancements

- add support for additional EC2 event patterns if needed
- add SNS or email alerting for remediation events
- deploy with Terraform or CloudFormation
- add architecture diagrams and screenshots
- build an Azure NSG equivalent version
