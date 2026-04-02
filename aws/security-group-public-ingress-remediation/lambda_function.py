import json
import boto3

# Create an EC2 client so this Lambda can call AWS EC2 APIs.
# We use it to:
# 1. look up Security Groups
# 2. remove public inbound rules
ec2 = boto3.client("ec2")

# If a Security Group has this tag, the Lambda will skip remediation.
EXCEPTION_TAG_KEY = "AllowPublicIngress"
EXCEPTION_TAG_VALUE = "true"


def has_exception_tag(security_group):
    """
    Check whether the Security Group has the approved exception tag.

    If the tag AllowPublicIngress=true exists, we do not remediate it.
    """
    tags = security_group.get("Tags", [])

    for tag in tags:
        if (
            tag.get("Key") == EXCEPTION_TAG_KEY
            and str(tag.get("Value", "")).lower() == EXCEPTION_TAG_VALUE
        ):
            return True

    return False


def get_security_group(group_id):
    """
    Retrieve the full Security Group object from AWS using the group ID.
    """
    response = ec2.describe_security_groups(GroupIds=[group_id])
    groups = response.get("SecurityGroups", [])

    if not groups:
        raise ValueError(f"Security group not found: {group_id}")

    return groups[0]


def revoke_public_ingress(group_id, security_group):
    """
    Loop through all inbound rules on the Security Group and remove any rule
    that allows public access from:
    - 0.0.0.0/0
    - ::/0

    Returns a list of the rules that were removed.
    """
    revoked_rules = []

    # Inbound rules are stored in IpPermissions
    for permission in security_group.get("IpPermissions", []):
        # Find any public IPv4 ranges on this permission
        public_ipv4 = [
            r for r in permission.get("IpRanges", [])
            if r.get("CidrIp") == "0.0.0.0/0"
        ]

        # Find any public IPv6 ranges on this permission
        public_ipv6 = [
            r for r in permission.get("Ipv6Ranges", [])
            if r.get("CidrIpv6") == "::/0"
        ]

        # If this rule is not public, skip it
        if not public_ipv4 and not public_ipv6:
            continue

        # Build the exact payload AWS expects to revoke only the bad part
        # of the inbound rule.
        revoke_payload = {
            "GroupId": group_id,
            "IpPermissions": [
                {
                    "IpProtocol": permission.get("IpProtocol"),
                    "FromPort": permission.get("FromPort"),
                    "ToPort": permission.get("ToPort"),
                    "IpRanges": public_ipv4,
                    "Ipv6Ranges": public_ipv6,
                    "PrefixListIds": [],
                    "UserIdGroupPairs": []
                }
            ]
        }

        # Remove the public inbound rule from the Security Group
        ec2.revoke_security_group_ingress(**revoke_payload)

        # Save what we removed so it shows up in logs / response
        revoked_rules.append(
            {
                "IpProtocol": permission.get("IpProtocol"),
                "FromPort": permission.get("FromPort"),
                "ToPort": permission.get("ToPort"),
                "IpRanges": public_ipv4,
                "Ipv6Ranges": public_ipv6,
            }
        )

    return revoked_rules


def extract_group_id_from_event(event):
    """
    Try to pull the Security Group ID from:
    1. Manual test events
    2. AuthorizeSecurityGroupIngress CloudTrail events
    3. ModifySecurityGroupRules CloudTrail events

    Returns:
        group_id string if found
        None if not found
    """

    # Manual test path:
    # Example: { "group_id": "sg-1234567890" }
    if event.get("group_id"):
        return event.get("group_id")

    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    request_parameters = detail.get("requestParameters", {})

    print(f"Detected eventName: {event_name}")
    print("requestParameters:")
    print(json.dumps(request_parameters, indent=2))

    # Path for AuthorizeSecurityGroupIngress events
    # These commonly use requestParameters.groupId
    if request_parameters.get("groupId"):
        return request_parameters.get("groupId")

    # Path for ModifySecurityGroupRules events
    # Your real event shows:
    # requestParameters.ModifySecurityGroupRulesRequest.GroupId
    modify_request = request_parameters.get("ModifySecurityGroupRulesRequest", {})
    if modify_request.get("GroupId"):
        return modify_request.get("GroupId")

    # If nothing matched, return None
    return None


def lambda_handler(event, context):
    """
    Main Lambda entry point.

    Supported inputs:
    1. Manual test:
       { "group_id": "sg-..." }

    2. CloudTrail/EventBridge events for:
       - AuthorizeSecurityGroupIngress
       - ModifySecurityGroupRules

    Flow:
    - log the event
    - extract the Security Group ID
    - retrieve the Security Group
    - check for exception tag
    - remove any public inbound rules
    - return a summary
    """
    print("Received event:")
    print(json.dumps(event, indent=2))

    group_id = extract_group_id_from_event(event)

    if not group_id:
        error_message = "Could not determine Security Group ID from event"
        print(error_message)
        return {
            "statusCode": 400,
            "body": json.dumps(error_message)
        }

    security_group = get_security_group(group_id)

    # If the SG is explicitly exempt, do nothing
    if has_exception_tag(security_group):
        message = f"Security group {group_id} has exception tag. No remediation performed."
        print(message)
        return {
            "statusCode": 200,
            "body": json.dumps(message)
        }

    # Otherwise remove any public inbound rules
    revoked_rules = revoke_public_ingress(group_id, security_group)

    message = {
        "group_id": group_id,
        "revoked_rule_count": len(revoked_rules),
        "revoked_rules": revoked_rules
    }

    print("Remediation result:")
    print(json.dumps(message, indent=2))

    return {
        "statusCode": 200,
        "body": json.dumps(message)
    }
