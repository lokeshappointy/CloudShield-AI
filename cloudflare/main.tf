terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0" // Use the latest 4.x version
    }
  }
  # If you plan to use Terraform Cloud or another backend, configure it here
  # backend "remote" { ... }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
  # Or use environment variables: CLOUDFLARE_API_TOKEN
}

# --- WAF Module Instance ---
module "waf_custom_rules" {
  source             = "./modules/waf"
  zone_id            = var.cloudflare_zone_id
  custom_waf_rules   = var.waf_rules
}

# --- Rate Limit Module Instance ---
module "ratelimit_rules" {
  source                 = "./modules/ratelimit"
  zone_id                = var.cloudflare_zone_id
  custom_ratelimit_rules = var.ratelimit_rules
}

# --- Outputs (Optional but good for verification) ---
output "waf_custom_ruleset_id" {
  description = "ID of the WAF custom ruleset"
  value       = module.waf_custom_rules.waf_ruleset_id
}

output "waf_custom_ruleset_name" {
  description = "Name of the WAF custom ruleset"
  value       = module.waf_custom_rules.waf_ruleset_name
}

output "ratelimit_ruleset_id" {
  description = "ID of the Rate Limiting ruleset"
  value       = module.ratelimit_rules.ratelimit_ruleset_id
}

output "ratelimit_ruleset_name" {
  description = "Name of the Rate Limiting ruleset"
  value       = module.ratelimit_rules.ratelimit_ruleset_name
}