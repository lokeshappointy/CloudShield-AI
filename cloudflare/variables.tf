variable "cloudflare_api_token" {
  description = "Cloudflare API Token"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID for your domain. For Appointy.ai, this is 'a747b0922844085a36a5b4a04e645a19'."
  type        = string
}

variable "waf_rules" {
  description = "A list of WAF rules definitions for the http_request_firewall_custom ruleset."
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
    { // Rule 1
      action      = "skip"
      description = "[SKIP] GCP Infrastructure - CloudBuild "
      enabled     = true
      expression  = "(ip.src.asnum eq 396982 and ip.src.country eq \"BE\" and http.user_agent eq \"app/1.0.0\")" // No direct ip.src eq/ne here
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed"], products = ["uaBlock"] }
      logging     = { enabled = true }
    },
    { // Rule 2
      action      = "skip"
      description = "[SKIP] GCP Infrastructure - Belgium "
      enabled     = true
      expression  = "(ip.src.asnum eq 396982 and ip.src.country eq \"BE\" and http.user_agent eq \"Go-http-client/2.0\")" // No direct ip.src eq/ne here
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed"], products = ["uaBlock"] }
      logging     = { enabled = true }
    },
    { // Rule 3
      action      = "skip"
      description = "[SKIP] API - Meta "
      enabled     = true
      expression  = "(http.user_agent eq \"facebookplatform/1.0 (+http://developers.facebook.com)\") or (http.user_agent eq \"Webhooks/1.0 (https://fb.me/webhooks)\") or (http.request.uri.path contains \"integration/v1/messages/webhook/instagram\")" // No direct ip.src eq/ne here
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"], products = ["bic", "rateLimit", "uaBlock", "waf"] }
      logging     = { enabled = true }
    },
    { // Rule 4
      action      = "skip"
      description = "[SKIP] Appointy AI Auth"
      enabled     = true
      // For ip.src eq IP_ADDRESS, the IP should NOT be quoted.
      expression  = "(http.host eq \"qa-api.appointy.ai\" and starts_with(http.request.uri.path, \"/auth/\") and ip.src eq 54.86.50.139)" // IP NOT QUOTED
      action_parameters = { ruleset  = "current", phases   = ["http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"], products = ["bic", "rateLimit", "securityLevel", "uaBlock", "waf"] }
      logging     = { enabled = true }
    },
    { // Rule 5
      action      = "skip"
      description = "[SKIP] Office IP Level 7"
      enabled     = true
      expression  = "(ip.src eq 49.249.139.126)" // IP NOT QUOTED
      action_parameters = { ruleset  = "current", phases   = ["http_request_firewall_managed"], products = null }
      logging     = { enabled = true }
    },
    { // Rule 6
      action      = "skip"
      description = "[SKIP] Office IP Level 6"
      enabled     = true
      expression  = "(ip.src eq 49.249.139.125 or ip.src eq 35.209.92.243)" // IPs NOT QUOTED
      action_parameters = { ruleset  = "current", phases   = ["http_request_firewall_managed"], products = null }
      logging     = { enabled = true }
    },
    { // Rule 7
      action      = "skip"
      description = "[SKIP] Office IP Level 5"
      enabled     = true
      expression  = "(ip.src eq 49.249.139.124)" // IP NOT QUOTED
      action_parameters = { ruleset  = "current", phases   = ["http_request_firewall_managed"], products = null }
      logging     = { enabled = true }
    },
    { // Rule 8
      action      = "block"
      description = "[SKIP] Office IP Level 4"
      enabled     = true
      expression  = "(ip.src ne 49.249.139.123)" // IP NOT QUOTED
      action_parameters = null
      logging     = null
    }
  ]
}

variable "ratelimit_rules" {
  description = "A list of Rate Limiting rules to create"
  type = list(object({
    name                       = string
    description                = string
    match_request_uri_path     = string 
    expression_override        = optional(string)
    match_response_headers     = optional(list(object({ name = string, op = string, value = string })), [])
    characteristics            = list(string)
    period_seconds             = number
    requests_per_period        = number
    mitigation_timeout_seconds = number
    action                     = string
    enabled                    = optional(bool, true)
  }))
  default = [
    // Example: Add your NEW rate limit rule for waf-test.appointy.ai here
    // This will be created as a new rate limit ruleset if no existing one is imported/managed.
    // {
    //   name                  = "Test Rate Limit for waf-test.appointy.ai"
    //   description           = "Rate limit for waf-test.appointy.ai"
    //   match_request_uri_path = ".*" 
    //   expression_override   = "(http.host eq \"waf-test.appointy.ai\") and (http.request.uri.path matches \".*\")" // Example full expression
    //   characteristics       = ["ip.src", "cf.colo.id"] 
    //   period_seconds        = 60 
    //   requests_per_period   = 100 
    //   mitigation_timeout_seconds = 60 
    //   action                = "block" 
    //   enabled               = true
    // },
  ]
}