variable "cloudflare_api_token" {
  description = "Cloudflare API Token"
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID for your domain"
  type        = string
}

variable "waf_rules" {
  description = "A list of WAF rules to create"
  type = list(object({
    name        = string
    description = string
    expression  = string
    action      = string // e.g., "block", "challenge", "log", "managed_challenge", "js_challenge"
  }))
  default = [
    {
      name        = "Block Common Login Page Probes"
      description = "Blocks common dictionary attack patterns on login pages via POST"
      expression  = <<EOT
(http.request.uri.path contains "/login" and http.request.method eq "POST") or
(http.request.uri.path contains "/wp-login.php" and http.request.method eq "POST") or
(http.request.uri.path contains "/admin" and http.request.method eq "POST" and not http.request.uri.path matches "^/admin/api/some-legit-path") or # Example exclusion
(http.request.uri.path contains "/administrator" and http.request.method eq "POST") or
(http.request.uri.path contains "/signin" and http.request.method eq "POST")
EOT
      action      = "block" // Consider "challenge" or "managed_challenge" for less impact initially
    },
    {
      name        = "Block SQL Injection Attempts in Query String"
      description = "Basic SQLi pattern detection in query string"
      expression  = "(lower(http.request.uri.query) contains \"select\" and lower(http.request.uri.query) contains \"from\") or (lower(http.request.uri.query) contains \"union\" and lower(http.request.uri.query) contains \"select\") or (lower(http.request.uri.query) contains \"drop table\")"
      action      = "block"
    },
    // Add more predefined WAF rules here if needed
  ]
}

variable "ratelimit_rules" {
  description = "A list of Rate Limiting rules to create"
  type = list(object({
    name                  = string
    description           = string
    match_request_uri_path = string // Regex for URI path
    match_response_headers = optional(list(object({ 
        name = string
        op = string 
        value = string
    })), [])
    characteristics       = list(string) // e.g., ["ip.src", "cf.colo.id"]
    period_seconds        = number       // e.g., 10, 60
    requests_per_period   = number       // e.g., 5, 100
    mitigation_timeout_seconds = number  // Must be 0, equal to period, or > period
    action                = string       // e.g., "block", "challenge", "js_challenge", "log"
    enabled               = optional(bool, true)
  }))
  default = [
    // *** FREE PLAN: LIKELY ONLY ONE OF THESE RULES CAN BE ACTIVE ***
    // *** CHOOSE ONE OR UPGRADE YOUR CLOUDFLARE PLAN ***
    {
      name                  = "Login Attempts Rate Limit"
      description           = "Rate limit excessive login attempts to common login paths"
      match_request_uri_path = "^/(login|wp-login\\.php|admin|administrator|signin)$"
      characteristics       = ["ip.src", "cf.colo.id"] // Added cf.colo.id
      period_seconds        = 10  // 10 minutes
      requests_per_period   = 10   // 10 login attempts
      // Set mitigation_timeout_seconds to be equal to period_seconds
      mitigation_timeout_seconds = 10
      action                = "block"
      enabled               = true
    },
    // { // Comment out or remove this second rule if on the Free plan
    //   name                  = "General API Rate Limit"
    //   description           = "Rate limit general API requests"
    //   match_request_uri_path = "^/api/.*"
    //   characteristics       = ["ip.src", "cf.colo.id"] // Added cf.colo.id
    //   period_seconds        = 60   // 1 minute
    //   requests_per_period   = 100
    //   // Set mitigation_timeout_seconds to be equal to period_seconds
    //   mitigation_timeout_seconds = 60
    //   action                = "block"
    //   enabled               = true
    // },
  ]
}