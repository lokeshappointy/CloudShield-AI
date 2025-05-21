# CloudShield-AI: Cloudflare WAF and Rate Limiting Management

This directory (`cloudflare/`) contains the Terraform configuration for managing Web Application Firewall (WAF) custom rules and Rate Limiting rules for specified Cloudflare zones. It is part of the larger CloudShield-AI project, which aims to provide an intelligent, automated security pipeline.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Directory Structure](#3-directory-structure)
4. [Configuration Details](#4-configuration-details)

   * [Variables](#variables)
   * [Rule Definitions](#rule-definitions)
   * [Modules](#modules)
5. [Local Development and Usage](#5-local-development-and-usage)

   * [Initial Setup](#initial-setup)
   * [Planning Changes](#planning-changes)
   * [Applying Changes](#applying-changes)
   * [Managing Rules](#managing-rules)
6. [State Management](#6-state-management)
7. [CI/CD Automation (GitHub Actions)](#7-cicd-automation-github-actions)
8. [Important Considerations](#8-important-considerations)

---

## 1. Overview

This Terraform setup automates the provisioning and management of:

* **Custom WAF Rules:** Managed under a Cloudflare Ruleset with `phase = "http_request_firewall_custom"`, including imported existing rules and newly defined rules targeting threats such as SQL injection or dictionary attacks.
* **Rate Limiting Rules:** Managed under a `phase = "http_ratelimit"` ruleset to throttle abusive traffic and mitigate denial-of-service attacks.

The configuration follows a modular structure, separating rule definitions from resource logic for better maintainability.

---

## 2. Prerequisites

* **Terraform CLI:** Version `1.1.2` or higher (preferably `1.6.6` or newer).
* **Cloudflare Account:** Must have a **Pro Plan** or higher to enable necessary features.
* **Cloudflare API Token:** With permissions:

  * Zone > Zone Settings: Read
  * Zone > Firewall Services: Edit (or WAF\:Edit, Rate Limiting\:Edit, Zone Rulesets\:Edit)
* **Cloudflare Zone ID:** ID of the target zone (e.g., `appointy.ai`).
* **GitHub Repository:** For enabling CI/CD using GitHub Actions.
* **Remote Backend (Recommended):** For managing Terraform state securely.

---

## 3. Directory Structure

```plaintext
cloudflare/
├── main.tf                    # Root module: provider config, module invocations, outputs
├── variables.tf               # Root variable declarations
├── terraform.tfvars           # Variable values for local development
├── backend.tf                 # Remote state backend configuration (optional but recommended)
├── .terraform.lock.hcl        # Provider lock file
└── modules/
    ├── waf/
    │   ├── main.tf            # WAF ruleset definition
    │   └── variables.tf       # WAF input variables
    └── ratelimit/
        ├── main.tf            # Rate limiting ruleset definition
        └── variables.tf       # Rate limiting input variables
```

CI/CD-related workflows are stored under `.github/workflows/` in the root directory.

---

## 4. Configuration Details

### Variables

Declared in `variables.tf`, values are provided via:

* `terraform.tfvars` (local dev)
* `TF_VAR_` environment variables (in CI/CD)

Key variables include:

* `cloudflare_api_token` *(sensitive)*
* `cloudflare_zone_id`
* `baseline_waf_rules`: List of WAF rule objects
* `ratelimit_rules`: List of rate limiting rule objects

### Rule Definitions

**WAF Rule Object Structure (`baseline_waf_rules`):**

```hcl
{
  action      = "block" | "challenge" | "skip" | "managed_challenge"
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
}
```

**Rate Limiting Rule Object Structure (`ratelimit_rules`):**

```hcl
{
  name                       = string
  description                = string
  match_request_uri_path     = string
  expression_override        = string
  characteristics            = list(string)
  period_seconds             = number
  requests_per_period        = number
  mitigation_timeout_seconds = number
  action                     = "block" | "challenge"
  enabled                    = optional(bool, true)
}
```

Refer to [Cloudflare Docs](https://developers.cloudflare.com/ruleset-engine/) for updated syntax and field capabilities.

### Modules

* **modules/waf:** Manages the zone-level ruleset named `default` with phase `http_request_firewall_custom`.
* **modules/ratelimit:** Manages the ruleset named `Terraform Managed Rate Limiting` with phase `http_ratelimit`.

---

## 5. Local Development and Usage

All Terraform commands should be executed from the `cloudflare/` directory.

### Initial Setup

1. **Install Terraform CLI** (>= v1.1.2)
2. **Set API Token & Zone ID** (recommended via shell env):

   ```bash
   export TF_VAR_cloudflare_api_token="YOUR_API_TOKEN"
   export TF_VAR_cloudflare_zone_id="YOUR_ZONE_ID"
   ```
3. **Prepare `terraform.tfvars`**:

   ```hcl

   baseline_waf_rules = [
     // ... rule objects ...
   ]

   ratelimit_rules = [
     // ... rule objects ...
   ]
   ```
4. **Initialize Terraform:**

   ```bash
   terraform init
   ```

### Planning Changes

To preview changes:

```bash
terraform plan
```

To save a plan:

```bash
terraform plan -out=tfplan.out
```

### Applying Changes

Apply a saved plan:

```bash
terraform apply tfplan.out
```

Or apply interactively:

```bash
terraform apply
```

To skip confirmation (use with caution):

```bash
terraform apply -auto-approve
```

### Managing WAF & Rate Limiting Rules

> You can easily add, update, or delete rules by modifying `terraform.tfvars`.

#### 🔒 WAF Rules (`baseline_waf_rules`)

* **Add**: Append a new rule object to the `baseline_waf_rules` list.

  **Example:**

  ```hcl
  {
    action      = "challenge",
    description = "WAF Test: Apply challenge to /suspicious",
    enabled     = true,
    expression  = <<EOT
      (http.host eq "waf-test.appointy.ai") and 
      (http.request.uri.path eq "/suspicious")
    EOT,s
    action_parameters = null
  }
  ```

* **Update**: Modify fields like `expression`, `action`, or `description`.

* **Delete**: Remove the object from the list.

#### 🚦 Rate Limiting Rules (`ratelimit_rules`)

* **Add**: Append a new rule object to the list similar to waf but with different parameters .
* **Update/Delete**: Modify or remove as needed.

✅ After any changes:

```bash
terraform plan
terraform apply
```

> Tip: Use meaningful descriptions and test expressions carefully.

---

## 6. State Management

Terraform stores infrastructure mappings in a state file (`terraform.tfstate`).

### Local State (Default)

* Suitable for solo development
* Add `terraform.tfstate` to `.gitignore`

### Remote Backend (Recommended)

* Enables locking, collaboration, and versioning
* Example using Google Cloud Storage:

```hcl
terraform {
  backend "gcs" {
    bucket = "your-tf-state-bucket"
    prefix = "cloudflare-infra/appointy-ai/state"
  }
}
```

Run `terraform init` to initialize or migrate the state backend.

---

## 7. CI/CD Automation (GitHub Actions)

A workflow is defined in `.github/workflows/terraform-cloudflare.yml`.

### Triggers

* **Push to `main`**: Triggers the CICD pipeline

### Scope

* Changes only within `cloudflare/` or the workflow file trigger the pipeline

### Secrets Required

* `CLOUDFLARE_API_TOKEN`
* `CLOUDFLARE_ZONE_ID`

---

## 8. Important Considerations

* Test rule expressions carefully before applying.
* Avoid hardcoding sensitive credentials.
* Always review `terraform plan` outputs before applying.
* Use remote state in production setups.
* Follow Cloudflare's rate limits and plan constraints.

---

