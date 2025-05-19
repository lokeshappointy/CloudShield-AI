variable "cloudflare_api_token" {
  description = "Cloudflare API Token (set via TF_VAR environment variable)"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID for your domain. For Appointy.ai, this is 'a747b0922844085a36a5b4a04e645a19'."
  type        = string
}

variable "baseline_waf_rules" { // Renamed from waf_rules for clarity if you adopt locals later
  description = "Baseline WAF rules (imported existing + predefined new rules)."
  type = list(object({
    action      = string
    description = string
    enabled     = optional(bool, true)
    expression  = string
    action_parameters = optional(object({
      ruleset  = optional(string)
      phases   = optional(list(string))
      products = optional(list(string))
    }), null)
    logging = optional(object({
      enabled = bool
    }), null)
  }))
  default = [
    // --- BEGIN: All 8 Existing Rules (as defined and fixed previously) ---
    { // Rule 1
      action      = "skip"
      description = "[SKIP] GCP Infrastructure - CloudBuild "
      enabled     = true
      expression  = "(ip.src.asnum eq 396982 and ip.src.country eq \"BE\" and http.user_agent eq \"app/1.0.0\")"
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed"], products = ["uaBlock"] }
      logging     = { enabled = true }
    },
    { // Rule 2
      action      = "skip"
      description = "[SKIP] GCP Infrastructure - Belgium "
      enabled     = true
      expression  = "(ip.src.asnum eq 396982 and ip.src.country eq \"BE\" and http.user_agent eq \"Go-http-client/2.0\")"
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed"], products = ["uaBlock"] }
      logging     = { enabled = true }
    },
    { // Rule 3
      action      = "skip"
      description = "[SKIP] API - Meta "
      enabled     = true
      expression  = "(http.user_agent eq \"facebookplatform/1.0 (+http://developers.facebook.com)\") or (http.user_agent eq \"Webhooks/1.0 (https://fb.me/webhooks)\") or (http.request.uri.path contains \"integration/v1/messages/webhook/instagram\")"
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"], products = ["bic", "rateLimit", "uaBlock", "waf"] }
      logging     = { enabled = true }
    },
    { // Rule 4
      action      = "skip"
      description = "[SKIP] Appointy AI Auth"
      enabled     = true
      expression  = "(http.host eq \"qa-api.appointy.ai\" and starts_with(http.request.uri.path, \"/auth/\") and ip.src eq 54.86.50.139)"
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"], products = ["bic", "rateLimit", "securityLevel", "uaBlock", "waf"] }
      logging     = { enabled = true }
    },
    { // Rule 5
      action      = "skip"
      description = "[SKIP] Office IP Level 7"
      enabled     = true
      expression  = "(ip.src eq 49.249.139.126)"
      action_parameters = { ruleset  = "current", phases   = ["http_request_firewall_managed"], products = null }
      logging     = { enabled = true }
    },
    { // Rule 6
      action      = "skip"
      description = "[SKIP] Office IP Level 6"
      enabled     = true
      expression  = "(ip.src eq 49.249.139.125 or ip.src eq 35.209.92.243)"
      action_parameters = { ruleset  = "current", phases   = ["http_request_firewall_managed"], products = null }
      logging     = { enabled = true }
    },
    { // Rule 7
      action      = "skip"
      description = "[SKIP] Office IP Level 5"
      enabled     = true
      expression  = "(ip.src eq 49.249.139.124)"
      action_parameters = { ruleset  = "current", phases   = ["http_request_firewall_managed"], products = null }
      logging     = { enabled = true }
    },
    { // Rule 8
      action      = "block"
      description = "[SKIP] Office IP Level 4"
      enabled     = true
      expression  = "(ip.src ne 49.249.139.123)"
      action_parameters = null
      logging     = null
    },
    // --- END: All 8 Existing Rules ---

    // --- BEGIN: Predefined NEW WAF Rules for waf-test.appointy.ai ---
    {
      action      = "challenge" // Action is "challenge" (allowed)
      description = "WAF Test: Dictionary Attack on Login (waf-test.appointy.ai)"
      enabled     = true
      expression  = <<EOT
(http.host eq "waf-test.appointy.ai") and 
(http.request.method eq "POST") and 
(
  starts_with(http.request.uri.path, "/login") or
  starts_with(http.request.uri.path, "/signin") or
  starts_with(http.request.uri.path, "/admin") or
  starts_with(http.request.uri.path, "/administrator") or
  starts_with(http.request.uri.path, "/wp-login.php")
)
EOT
      action_parameters = null 
      logging     = null // Correct, logging only for "skip" action
    },
    {
      action      = "challenge" // Start with "log"
      description = "WAF Test: SQLi Attempt in Query String (waf-test.appointy.ai)"
      enabled     = true
      expression  = "(http.host eq \"waf-test.appointy.ai\") and ((lower(http.request.uri.query) contains \"select\" and lower(http.request.uri.query) contains \"from\") or (lower(http.request.uri.query) contains \"union select\") or (lower(http.request.uri.query) contains \"drop table\"))"
      action_parameters = null
      logging     = null
    }
    // --- END: Predefined NEW WAF Rules ---
  ]
}

variable "ratelimit_rules" {
  description = "A list of Rate Limiting rules to create"
  type = list(object({
    name                       = string
    description                = string
    match_request_uri_path     = string 
    expression_override        = string // Assuming non-optional string now
    match_response_headers     = optional(list(object({ name = string, op = string, value = string })), [])
    characteristics            = list(string)
    period_seconds             = number
    requests_per_period        = number
    mitigation_timeout_seconds = number
    action                     = string
    enabled                    = optional(bool, true)
  }))
  default = [
    {
      name                       = "RL General Site Limit waf-test"
      description                = "General rate limit for waf-test.appointy.ai"
      match_request_uri_path     = ".*"
      expression_override        = "(http.host eq \"waf-test.appointy.ai\") and (http.request.uri.path contains \"\")" 
      characteristics            = ["ip.src", "cf.colo.id"]
      period_seconds             = 60 // Allowed period
      requests_per_period        = 20 
      mitigation_timeout_seconds = 60 // Matched to period
      action                     = "block"
      enabled                    = true
    },
    {
      name                       = "RL Login Attempts waf-test"
      description                = "Rate limit login attempts on waf-test.appointy.ai"
      match_request_uri_path     = "^/(login|signin|admin|administrator|wp-login\\.php)$"
      // REMOVED: (http.request.method eq "POST") and
      expression_override        = <<EOT
(http.host eq "waf-test.appointy.ai") and 
(
  starts_with(http.request.uri.path, "/login") or
  starts_with(http.request.uri.path, "/signin") or
  starts_with(http.request.uri.path, "/admin") or
  starts_with(http.request.uri.path, "/administrator") or
  starts_with(http.request.uri.path, "/wp-login.php")
)
EOT
      characteristics            = ["ip.src", "cf.colo.id"]
      period_seconds             = 60 // Changed to an allowed period
      requests_per_period        = 10 // Adjust threshold if period changed significantly
      mitigation_timeout_seconds = 60 // Matched to period
      action                     = "block"
      enabled                    = true
    }
  ]
}