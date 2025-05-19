variable "zone_id" {
  description = "Cloudflare Zone ID"
  type        = string
}

variable "custom_ratelimit_rules" {
  description = "A list of Rate Limiting rules definitions"
  type = list(object({
    name                  = string
    description           = string
    match_request_uri_path = string
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
  default = []
}