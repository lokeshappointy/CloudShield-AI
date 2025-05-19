variable "zone_id" {
  description = "Cloudflare Zone ID"
  type        = string
}

variable "custom_waf_rules" {
  description = "A list of WAF rules definitions"
  type = list(object({
    name        = string
    description = string
    expression  = string
    action      = string
  }))
  default     = []
}