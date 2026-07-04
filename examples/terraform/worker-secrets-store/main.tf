terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 5.0.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.0.0"
    }
  }
}

provider "cloudflare" {}
provider "vault" {}

variable "account_id" {
  type = string
}

variable "secrets_store_id" {
  type = string
}

variable "vault_cloudflare_mount" {
  type    = string
  default = "cloudflare"
}

variable "worker_script_name" {
  type    = string
  default = "vault-cloudflare-example"
}

resource "vault_generic_endpoint" "api_jwt_rule" {
  path                 = "${var.vault_cloudflare_mount}/sync/rules/api-jwt"
  ignore_absent_fields = true

  data_json = jsonencode({
    vault_mount      = "kv"
    vault_path       = "apps/api/prod/jwt_private_key"
    vault_field      = "value"
    cloudflare_name  = "JWT_PRIVATE_KEY"
    binding_name     = "JWT_PRIVATE_KEY"
    secrets_store_id = var.secrets_store_id
    scopes           = "workers"
    split            = "auto"
    encoding         = "raw"
    enabled          = true
  })
}

resource "terraform_data" "sync_api_jwt" {
  depends_on = [vault_generic_endpoint.api_jwt_rule]

  triggers_replace = [
    vault_generic_endpoint.api_jwt_rule.data_json,
  ]

  provisioner "local-exec" {
    command = "vault write ${var.vault_cloudflare_mount}/sync/run/api-jwt"
  }
}

data "vault_generic_secret" "api_jwt_bindings" {
  depends_on = [terraform_data.sync_api_jwt]
  path       = "${var.vault_cloudflare_mount}/sync/bindings/api-jwt"
}

locals {
  api_jwt_bindings = jsondecode(data.vault_generic_secret.api_jwt_bindings.data["bindings_json"])
}

resource "cloudflare_workers_script" "api" {
  depends_on = [terraform_data.sync_api_jwt]

  account_id  = var.account_id
  script_name = var.worker_script_name
  content     = file("${path.module}/worker.js")
  bindings    = local.api_jwt_bindings
}
