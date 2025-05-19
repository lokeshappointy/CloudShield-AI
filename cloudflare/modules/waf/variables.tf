variable "zone_id" {
  description = "Cloudflare Zone ID"
  type        = string
}

variable "custom_waf_rules" {
  description = "A list of WAF rules definitions for the http_request_firewall_custom ruleset."
  type = list(object({
    action      = string
    description = string
    enabled     = optional(bool, true)
    expression  = string
    action_parameters = optional(object({ // Keep this as defined before
      ruleset  = optional(string)
      phases   = optional(list(string))
      products = optional(list(string))
    }), null)
    logging = optional(object({ // ADDED logging attribute
      enabled = bool
    }), null)
  }))
  default = []
}

variable "ruleset_description" {
  description = "Description for the WAF ruleset."
  type        = string
  default     = "" // Default to empty string to match the current state
}