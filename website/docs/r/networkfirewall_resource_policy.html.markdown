---
subcategory: "Network Firewall"
layout: "aws"
page_title: "AWS: aws_networkfirewall_resource_policy"
description: |-
  Provides an AWS Network Firewall Resource Policy resource.
---

# Resource: aws_networkfirewall_resource_policy

Provides an AWS Network Firewall Resource Policy Resource for a rule group or firewall policy.

## Example Usage

### For a Firewall Policy resource

```hcl
resource "aws_networkfirewall_resource_policy" "example" {
  resource_arn = aws_networkfirewall_firewall_policy.example.arn
  policy = jsonencode({
    Statement = [{
      Action   = "network-firewall:ListFirewallPolicies"
      Effect   = "Allow"
      Resource = aws_networkfirewall_firewall_policy.test.arn
      Principal = {
        AWS = "arn:aws:iam::1234567890:user/example"
      }
    }]
    Version = "2012-10-17"
  })
}
```

### For a Rule Group resource

```hcl
resource "aws_networkfirewall_resource_policy" "test" {
  resource_arn = aws_networkfirewall_rule_group.test.arn
  policy = jsonencode({
    Statement = [{
      Action   = "network-firewall:ListRuleGroups"
      Effect   = "Allow"
      Resource = aws_networkfirewall_rule_group.test.arn
      Principal = {
        AWS = "arn:aws:iam::1234567890:user/example"
      }
    }]
    Version = "2012-10-17"
  })
}
```

## Argument Reference

The following arguments are supported:

* `policy` - (Required) JSON formatted policy document that controls access to the Network Firewall resource.

* `resource_arn` - (Required, Forces new resource) The Amazon Resource Name (ARN) of the rule group or firewall policy.

## Attribute Reference

In addition to all arguments above, the following attribute is exported:

* `id` - The Amazon Resource Name (ARN) of the rule group or firewall policy associated with the resource policy.

## Import

Network Firewall Resource Policies can be imported using the `resource_arn` e.g.

```
$ terraform import aws_networkfirewall_resource_policy.example aws_networkfirewall_rule_group.example arn:aws:network-firewall:us-west-1:123456789012:stateful-rulegroup/example
```
