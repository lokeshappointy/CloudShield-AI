terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

resource "cloudflare_ruleset" "custom_waf_ruleset" {
  count       = length(var.custom_waf_rules) > 0 ? 1 : 0
  zone_id     = var.zone_id
  name        = "Terraform Managed Custom WAF"
  description = "Custom WAF rules deployed via Terraform."
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  dynamic "rules" {
    for_each = { for rule in var.custom_waf_rules : rule.name => rule }
    content {
      action      = rules.value.action
      expression  = rules.value.expression // Directly uses the expression from the variable
      description = rules.value.description
      enabled     = true
    }
  }
}

output "waf_ruleset_id" {
  description = "The ID of the created WAF ruleset"
  value       = length(var.custom_waf_rules) > 0 ? cloudflare_ruleset.custom_waf_ruleset[0].id : "not_created"
}

output "waf_ruleset_name" {
  description = "The name of the created WAF ruleset"
  value       = length(var.custom_waf_rules) > 0 ? cloudflare_ruleset.custom_waf_ruleset[0].name : "not_created"
}