terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

resource "cloudflare_ruleset" "rate_limiting_ruleset" {
  count       = length(var.custom_ratelimit_rules) > 0 ? 1 : 0
  zone_id     = var.zone_id
  name        = "Terraform Managed Rate Limiting"
  description = "Rate limiting rules deployed via Terraform."
  kind        = "zone"
  phase       = "http_ratelimit"

  dynamic "rules" {
    for_each = { for idx, rule in var.custom_ratelimit_rules : rule.name => rule }
    content {
      action      = rules.value.action
      description = rules.value.description
      enabled     = rules.value.enabled

      // Use expression_override if provided, otherwise fallback to constructing from match_request_uri_path
      // The fallback here would still use 'matches', so ensure expression_override is always provided if matches is not allowed.
      expression  = try(rules.value.expression_override, "(http.request.uri.path matches \"${rules.value.match_request_uri_path}\")")

      ratelimit {
        characteristics       = rules.value.characteristics
        period                = rules.value.period_seconds
        requests_per_period   = rules.value.requests_per_period
        mitigation_timeout    = rules.value.mitigation_timeout_seconds
      }
    }
  }
}

output "ratelimit_ruleset_id" {
  description = "The ID of the created Rate Limit ruleset"
  value       = length(var.custom_ratelimit_rules) > 0 ? cloudflare_ruleset.rate_limiting_ruleset[0].id : "not_created"
}

output "ratelimit_ruleset_name" {
  description = "The name of the created Rate Limit ruleset"
  value       = length(var.custom_ratelimit_rules) > 0 ? cloudflare_ruleset.rate_limiting_ruleset[0].name : "not_created"
}