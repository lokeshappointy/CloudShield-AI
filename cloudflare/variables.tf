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
    expression  = string // This will now need to avoid 'matches'
    action      = string
  }))
  default = [
    {
      name        = "Block Common Login Page Probes"
      description = "Blocks common dictionary attack patterns on login pages via POST"
      # Removed 'matches' and the exclusion.
      # For the exclusion, you'd need more complex 'and not (condition_for_api_path)'
      # or accept that it might block the legit API path if it broadly matches /admin.
      # Simpler version without 'matches':
      expression  = <<EOT
(
  (http.request.uri.path contains "/login" and http.request.method eq "POST") or
  (http.request.uri.path contains "/wp-login.php" and http.request.method eq "POST") or
  (http.request.uri.path contains "/admin" and http.request.method eq "POST" and not starts_with(http.request.uri.path, "/admin/api/some-legit-path")) or // Using starts_with for exclusion
  (http.request.uri.path contains "/administrator" and http.request.method eq "POST") or
  (http.request.uri.path contains "/signin" and http.request.method eq "POST")
)
EOT
      action      = "block"
    },
    {
      name        = "Block SQL Injection Attempts in Query String"
      description = "Basic SQLi pattern detection in query string"
      # This rule already avoids 'matches' and should be fine.
      expression  = "(lower(http.request.uri.query) contains \"select\" and lower(http.request.uri.query) contains \"from\") or (lower(http.request.uri.query) contains \"union\" and lower(http.request.uri.query) contains \"select\") or (lower(http.request.uri.query) contains \"drop table\")"
      action      = "block"
    },
  ]
}

variable "ratelimit_rules" {
  description = "A list of Rate Limiting rules to create"
  type = list(object({
    name                  = string
    description           = string
    match_request_uri_path = string // For reference, not directly used in default expression
    expression_override   = optional(string)
    match_response_headers = optional(list(object({
        name = string
        op = string
        value = string
    })), [])
    characteristics       = list(string)
    period_seconds        = number
    requests_per_period   = number
    mitigation_timeout_seconds = number
    action                = string
    enabled               = optional(bool, true)
  }))
  default = [
    {
      name                  = "Login Attempts Rate Limit"
      description           = "Rate limit excessive login attempts to common login paths"
      match_request_uri_path = "^/(login|wp-login\\.php|admin|administrator|signin)$" // Reference
      expression_override   = <<EOT
(
  starts_with(http.request.uri.path, "/login") or
  starts_with(http.request.uri.path, "/wp-login.php") or
  starts_with(http.request.uri.path, "/admin") or
  starts_with(http.request.uri.path, "/administrator") or
  starts_with(http.request.uri.path, "/signin")
)
EOT
      characteristics       = ["ip.src", "cf.colo.id"]
      period_seconds        = 10
      requests_per_period   = 10
      mitigation_timeout_seconds = 10
      action                = "block"
      enabled               = true
    },
  ]
}