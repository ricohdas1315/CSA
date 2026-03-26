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

## Test 1 3/26 3:30PM
We have successfuly removed the inbound security gruop rule.
We created a default role and attached a inline policy to it as well to make sure it works. 
Have also created a lambda function and test security group to make sure it works. 
