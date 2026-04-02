# Notes

## Policy

Remove any inbound AWS Security Group rule that allows public access from `0.0.0.0/0` or `::/0`, unless the Security Group is tagged `AllowPublicIngress=true`.

## High-Level Flow

1. CloudTrail records Security Group ingress changes.
2. EventBridge matches relevant EC2 API events.
3. Lambda inspects the affected Security Group.
4. Lambda checks for the exception tag.
5. Lambda removes offending inbound public rule(s).
6. Lambda logs the result to CloudWatch.

## Event Coverage

- `AuthorizeSecurityGroupIngress`
- `ModifySecurityGroupRules`

## What Was Built

A Python-based AWS Lambda function that:
- parses either a manual test event or a real CloudTrail/EventBridge event
- extracts the affected Security Group ID
- retrieves the Security Group from AWS
- checks for the exception tag `AllowPublicIngress=true`
- removes any inbound rule containing `0.0.0.0/0` or `::/0`
- returns and logs the remediation result

## Proof of Concept Status

### Manual Remediation Testing
- Confirmed Lambda can remove public inbound Security Group rules when a Security Group ID is passed manually.
- Confirmed Lambda skips remediation when the Security Group is tagged `AllowPublicIngress=true`.

### Event-Driven Remediation Testing
- Confirmed EventBridge successfully triggered Lambda on `AuthorizeSecurityGroupIngress`.
- Confirmed EventBridge successfully triggered Lambda on `ModifySecurityGroupRules`.
- Confirmed Lambda automatically removed inbound rules exposing the Security Group to `0.0.0.0/0`.
- Confirmed exception-tagged Security Groups were not remediated.

## Cost Notes

- Lambda cost should remain negligible for a small personal lab.
- EventBridge cost should remain negligible for a small personal lab.
- CloudTrail was configured for management events only.
- S3 lifecycle expiration was set to 2 days to reduce storage retention.

## Next Steps

- add architecture diagram
- add screenshots of working remediation
- optionally add SNS/email alerting
- build Azure NSG version
