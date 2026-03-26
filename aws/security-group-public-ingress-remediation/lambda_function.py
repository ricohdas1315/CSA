import json
import boto3

ec2 = boto3.client("ec2")

EXCEPTION_TAG_KEY = "AllowPublicIngress"
EXCEPTION_TAG_VALUE = "true"


def has_exception_tag(security_group):
    tags = security_group.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == EXCEPTION_TAG_KEY and str(tag.get("Value", "")).lower() == EXCEPTION_TAG_VALUE:
            return True
    return False


def get_security_group(group_id):
    response = ec2.describe_security_groups(GroupIds=[group_id])
    groups = response.get("SecurityGroups", [])
    if not groups:
        raise ValueError(f"Security group not found: {group_id}")
    return groups[0]


def revoke_public_ingress(group_id, security_group):
    revoked_rules = []

    for permission in security_group.get("IpPermissions", []):
        public_ipv4 = [r for r in permission.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
        public_ipv6 = [r for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]

        if not public_ipv4 and not public_ipv6:
            continue

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

        ec2.revoke_security_group_ingress(**revoke_payload)

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


def lambda_handler(event, context):
    print("Received event:")
    print(json.dumps(event, indent=2))

    group_id = event.get("group_id")
    if not group_id:
        return {
            "statusCode": 400,
            "body": json.dumps("Missing 'group_id' in event")
        }

    security_group = get_security_group(group_id)

    if has_exception_tag(security_group):
        message = f"Security group {group_id} has exception tag. No remediation performed."
        print(message)
        return {
            "statusCode": 200,
            "body": json.dumps(message)
        }

    revoked_rules = revoke_public_ingress(group_id, security_group)

    message = {
        "group_id": group_id,
        "revoked_rule_count": len(revoked_rules),
        "revoked_rules": revoked_rules
    }

    print(json.dumps(message, indent=2))

    return {
        "statusCode": 200,
        "body": json.dumps(message)
    }
