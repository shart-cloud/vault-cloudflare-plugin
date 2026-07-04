package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const terraformSecretsStoreBindingType = "secrets_store_secret"

func (b *cloudflareBackend) pathSyncBindings() *framework.Path {
	return &framework.Path{
		Pattern: "sync/bindings/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Rule name.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathSyncBindingsRead},
		},
		HelpSynopsis:    "Read Terraform-friendly Worker Secrets Store binding metadata for a sync rule.",
		HelpDescription: "Plans the rule from the current Vault source and returns binding names, store IDs, and Cloudflare secret names without writing Cloudflare or returning secret values.",
	}
}

func (b *cloudflareBackend) pathSyncBindingsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ruleName := data.Get("name").(string)
	rule, err := readSyncRule(ctx, req.Storage, ruleName)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return logical.ErrorResponse("sync rule %q not found", ruleName), nil
	}
	if !rule.Enabled {
		return logical.ErrorResponse("sync rule %q is disabled", ruleName), nil
	}

	cfCfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfCfg == nil || cfCfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before reading sync bindings"), nil
	}
	syncCfg, err := readSyncConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if syncCfg == nil {
		syncCfg = defaultSyncConfig()
	}
	accountID := firstNonEmpty(rule.AccountID, cfCfg.AccountID)
	storeID := firstNonEmpty(rule.SecretsStoreID, cfCfg.SecretsStoreID)
	if accountID == "" || storeID == "" {
		return logical.ErrorResponse("account_id and secrets_store_id are required on the rule or config/cloudflare"), nil
	}

	source, err := b.readKVv2Source(ctx, req, rule)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	plan, err := buildSyncPlan(rule, syncCfg, source)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	bindings, err := buildTerraformSecretStoreBindings(rule, syncCfg, storeID, plan)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	bindingsJSON, err := json.Marshal(bindings)
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"rule_name":        rule.Name,
		"vault_path":       rule.VaultPath,
		"vault_version":    plan.VaultVersion,
		"account_id":       accountID,
		"store_id":         storeID,
		"binding_name":     effectiveWorkerBindingName(rule, syncCfg),
		"cloudflare_names": plannedNames(plan),
		"bindings":         bindings,
		"bindings_json":    string(bindingsJSON),
		"sha256":           plan.SourceSHA256,
	}}, nil
}

func buildTerraformSecretStoreBindings(rule *syncRule, syncCfg *syncConfig, storeID string, plan *syncPlan) ([]map[string]interface{}, error) {
	if storeID == "" {
		return nil, fmt.Errorf("store_id is required")
	}
	if plan == nil || len(plan.Secrets) == 0 {
		return nil, fmt.Errorf("sync plan has no planned secrets")
	}
	baseBindingName := effectiveWorkerBindingName(rule, syncCfg)
	if !isValidWorkerBindingName(baseBindingName) {
		return nil, fmt.Errorf("invalid binding name %q", baseBindingName)
	}

	parts, metadata := splitPlannedSecrets(plan)
	ordered := make([]plannedSecret, 0, len(plan.Secrets))
	ordered = append(ordered, metadata...)
	ordered = append(ordered, parts...)

	bindings := make([]map[string]interface{}, 0, len(ordered))
	for _, secret := range ordered {
		bindingName := baseBindingName
		if secret.Parts > 1 {
			if secret.Part == 0 || strings.HasSuffix(secret.Name, "__META") {
				bindingName = baseBindingName + "_META"
			} else {
				bindingName = fmt.Sprintf("%s_PART_%03d", baseBindingName, secret.Part)
			}
		}
		bindings = append(bindings, map[string]interface{}{
			"name":        bindingName,
			"type":        terraformSecretsStoreBindingType,
			"store_id":    storeID,
			"secret_name": secret.Name,
		})
	}
	return bindings, nil
}

func effectiveWorkerBindingName(rule *syncRule, syncCfg *syncConfig) string {
	if rule.BindingName != "" {
		return rule.BindingName
	}
	return sanitizeWorkerBindingName(syncRuleCloudflareBaseName(rule, syncCfg))
}

func sanitizeWorkerBindingName(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	var out strings.Builder
	lastUnderscore := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		valid := (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_'
		if !valid {
			if !lastUnderscore {
				out.WriteByte('_')
				lastUnderscore = true
			}
			continue
		}
		out.WriteByte(ch)
		lastUnderscore = ch == '_'
	}
	name := strings.Trim(out.String(), "_")
	if name == "" {
		name = "SECRET"
	}
	if name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}
	return name
}

func isValidWorkerBindingName(value string) bool {
	if value == "" {
		return false
	}
	first := value[0]
	if !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_') {
		return false
	}
	for i := 1; i < len(value); i++ {
		ch := value[i]
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_') {
			return false
		}
	}
	return true
}
