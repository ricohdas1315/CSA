# Notes

## Policy
Remove any inbound AWS Security Group rule that allows public access from 0.0.0.0/0 or ::/0, unless the Security Group is tagged `AllowPublicIngress=true`.

## High-level flow
1. CloudTrail records Security Group ingress changes.
2. EventBridge matches relevant events.
3. Lambda inspects the event and Security Group.
4. Lambda checks for exception tag.
5. Lambda removes offending inbound public rule(s).
6. Lambda logs the action.
