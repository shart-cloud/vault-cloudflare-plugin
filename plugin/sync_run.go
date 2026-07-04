package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const syncStateStoragePrefix = "state/sync/"

type syncState struct {
	LastRunAt           string            `json:"last_run_at,omitempty"`
	LastSuccessAt       string            `json:"last_success_at,omitempty"`
	LastError           string            `json:"last_error,omitempty"`
	VaultMount          string            `json:"vault_mount,omitempty"`
	VaultPath           string            `json:"vault_path,omitempty"`
	VaultField          string            `json:"vault_field,omitempty"`
	VaultVersion        int               `json:"vault_version,omitempty"`
	SourceSHA256        string            `json:"source_sha256,omitempty"`
	CloudflareAccountID string            `json:"cloudflare_account_id,omitempty"`
	CloudflareStoreID   string            `json:"cloudflare_store_id,omitempty"`
	CloudflareNamesToID map[string]string `json:"cloudflare_names_to_ids,omitempty"`
	Parts               int               `json:"parts,omitempty"`
}

func (b *cloudflareBackend) pathSyncRunAll() *framework.Path {
	return &framework.Path{
		Pattern: "sync/run",
		Fields: map[string]*framework.FieldSchema{
			"dry_run": {
				Type:        framework.TypeBool,
				Description: "Plan syncs without writing Cloudflare or sync state.",
			},
			"force": {
				Type:        framework.TypeBool,
				Description: "Patch Cloudflare entries even if stored state indicates no source change.",
			},
			"rule_prefix": {
				Type:        framework.TypeString,
				Description: "Optional prefix filter for explicit rule names.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSyncRunAllWrite},
		},
		HelpSynopsis:    "Run all enabled explicit sync rules.",
		HelpDescription: "Runs enabled explicit sync rules, optionally filtered by rule_prefix.",
	}
}

func (b *cloudflareBackend) pathSyncRunRule() *framework.Path {
	return &framework.Path{
		Pattern: "sync/run/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Rule name.",
			},
			"dry_run": {
				Type:        framework.TypeBool,
				Description: "Plan the sync without writing Cloudflare or sync state.",
			},
			"force": {
				Type:        framework.TypeBool,
				Description: "Patch Cloudflare entries even if stored state indicates no source change.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSyncRunRuleWrite},
		},
		HelpSynopsis:    "Run one explicit sync rule.",
		HelpDescription: "Reads the configured KV v2 source secret, plans any required chunking, and creates or patches Cloudflare Secrets Store entries.",
	}
}

func (b *cloudflareBackend) pathSyncStatus() *framework.Path {
	return &framework.Path{
		Pattern: "sync/status/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Rule name.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathSyncStatusRead},
		},
		HelpSynopsis:    "Read last sync status for a rule.",
		HelpDescription: "Returns the last stored sync state for a rule.",
	}
}

func (b *cloudflareBackend) pathSyncDelete() *framework.Path {
	return &framework.Path{
		Pattern: "sync/delete/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Rule name.",
			},
			"delete_cloudflare_secrets": {
				Type:        framework.TypeBool,
				Description: "Required confirmation to delete recorded Cloudflare Secrets Store entries.",
			},
			"dry_run": {
				Type:        framework.TypeBool,
				Description: "Report recorded Cloudflare entries without deleting them.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSyncDeleteWrite},
		},
		HelpSynopsis:    "Delete Cloudflare entries recorded for a sync rule.",
		HelpDescription: "Deletes Cloudflare Secrets Store entries from stored sync state. This never deletes the Vault source secret or the sync rule.",
	}
}

func (b *cloudflareBackend) pathSyncRunRuleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.runSyncRule(ctx, req, data.Get("name").(string), data.Get("dry_run").(bool), data.Get("force").(bool))
}

func (b *cloudflareBackend) pathSyncRunAllWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dryRun := data.Get("dry_run").(bool)
	force := data.Get("force").(bool)
	rulePrefix := data.Get("rule_prefix").(string)
	rules, err := readAllSyncRules(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	results := []map[string]interface{}{}
	errorsByRule := map[string]string{}
	for _, rule := range rules {
		if !rule.Enabled || (rulePrefix != "" && !strings.HasPrefix(rule.Name, rulePrefix)) {
			continue
		}
		resp, err := b.runSyncRule(ctx, req, rule.Name, dryRun, force)
		if err != nil {
			errorsByRule[rule.Name] = err.Error()
			continue
		}
		if resp != nil && resp.IsError() {
			errorsByRule[rule.Name] = resp.Error().Error()
			continue
		}
		if resp != nil {
			results = append(results, resp.Data)
		}
	}

	return &logical.Response{Data: map[string]interface{}{
		"dry_run": dryRun,
		"results": results,
		"errors":  errorsByRule,
	}}, nil
}

func (b *cloudflareBackend) runSyncRule(ctx context.Context, req *logical.Request, ruleName string, dryRun bool, force bool) (*logical.Response, error) {
	now := time.Now().UTC().Format(time.RFC3339)

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
		return logical.ErrorResponse("config/cloudflare must be configured before syncing"), nil
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
		_ = writeSyncState(ctx, req.Storage, ruleName, &syncState{LastRunAt: now, LastError: err.Error(), VaultMount: rule.VaultMount, VaultPath: rule.VaultPath, VaultField: rule.VaultField})
		return logical.ErrorResponse(err.Error()), nil
	}
	plan, err := buildSyncPlan(rule, syncCfg, source)
	if err != nil {
		_ = writeSyncState(ctx, req.Storage, ruleName, &syncState{LastRunAt: now, LastError: err.Error(), VaultMount: rule.VaultMount, VaultPath: rule.VaultPath, VaultField: rule.VaultField})
		return logical.ErrorResponse(err.Error()), nil
	}

	respData := map[string]interface{}{
		"rule_name":        ruleName,
		"vault_path":       rule.VaultPath,
		"vault_version":    plan.VaultVersion,
		"cloudflare_names": plannedNames(plan),
		"created":          []string{},
		"updated":          []string{},
		"deleted":          []string{},
		"unchanged":        []string{},
		"sha256":           plan.SourceSHA256,
		"warnings":         []string{},
		"dry_run":          dryRun,
	}
	if dryRun {
		return &logical.Response{Data: respData}, nil
	}

	state, err := readSyncState(ctx, req.Storage, ruleName)
	if err != nil {
		return nil, err
	}
	if !force && state != nil && state.SourceSHA256 == plan.SourceSHA256 && state.VaultVersion == plan.VaultVersion && sameStringSet(mapKeys(state.CloudflareNamesToID), plannedNames(plan)) {
		respData["unchanged"] = plannedNames(plan)
		return &logical.Response{Data: respData}, nil
	}

	client := newCloudflareClient(cfCfg, b.httpClient)
	remote, err := client.listSecrets(ctx, accountID, storeID)
	if err != nil {
		_ = writeSyncState(ctx, req.Storage, ruleName, &syncState{LastRunAt: now, LastError: err.Error(), VaultMount: rule.VaultMount, VaultPath: rule.VaultPath, VaultField: rule.VaultField})
		return nil, err
	}
	remoteByName := map[string]cloudflareSecret{}
	for _, secret := range remote {
		remoteByName[secret.Name] = secret
	}

	created := []string{}
	updated := []string{}
	deleted := []string{}
	namesToIDs := map[string]string{}
	parts, metadata := splitPlannedSecrets(plan)
	for _, pass := range [][]plannedSecret{parts, metadata} {
		for _, desired := range pass {
			createdName, updatedName, id, err := upsertPlannedSecret(ctx, client, accountID, storeID, remoteByName, desired)
			if err != nil {
				_ = writeSyncState(ctx, req.Storage, ruleName, &syncState{LastRunAt: now, LastError: err.Error(), VaultMount: rule.VaultMount, VaultPath: rule.VaultPath, VaultField: rule.VaultField})
				return nil, err
			}
			if createdName != "" {
				created = append(created, createdName)
			}
			if updatedName != "" {
				updated = append(updated, updatedName)
			}
			namesToIDs[desired.Name] = id
		}
	}
	if syncCfg.DeleteRemovedParts && state != nil {
		deleted, err = deleteStaleRecordedSecrets(ctx, client, accountID, storeID, state.CloudflareNamesToID, namesToIDs)
		if err != nil {
			_ = writeSyncState(ctx, req.Storage, ruleName, &syncState{LastRunAt: now, LastError: err.Error(), VaultMount: rule.VaultMount, VaultPath: rule.VaultPath, VaultField: rule.VaultField})
			return nil, err
		}
	}

	newState := &syncState{
		LastRunAt:           now,
		LastSuccessAt:       now,
		VaultMount:          rule.VaultMount,
		VaultPath:           rule.VaultPath,
		VaultField:          rule.VaultField,
		VaultVersion:        plan.VaultVersion,
		SourceSHA256:        plan.SourceSHA256,
		CloudflareAccountID: accountID,
		CloudflareStoreID:   storeID,
		CloudflareNamesToID: namesToIDs,
		Parts:               plan.Secrets[len(plan.Secrets)-1].Parts,
	}
	if err := writeSyncState(ctx, req.Storage, ruleName, newState); err != nil {
		return nil, err
	}

	respData["created"] = created
	respData["updated"] = updated
	respData["deleted"] = deleted
	return &logical.Response{Data: respData}, nil
}

func upsertPlannedSecret(ctx context.Context, client *cloudflareClient, accountID, storeID string, remoteByName map[string]cloudflareSecret, desired plannedSecret) (createdName string, updatedName string, id string, err error) {
	write := cloudflareSecretWrite{Name: desired.Name, Value: desired.Value, Scopes: desired.Scopes, Comment: desired.Comment}
	if existing, ok := remoteByName[desired.Name]; ok {
		secret, err := client.patchSecret(ctx, accountID, storeID, existing.ID, write)
		if err != nil {
			return "", "", "", err
		}
		return "", desired.Name, firstNonEmpty(secret.ID, existing.ID), nil
	}
	secret, err := client.createSecret(ctx, accountID, storeID, write)
	if err != nil {
		return "", "", "", err
	}
	return desired.Name, "", secret.ID, nil
}

func (b *cloudflareBackend) pathSyncStatusRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	state, err := readSyncState(ctx, req.Storage, data.Get("name").(string))
	if err != nil || state == nil {
		return nil, err
	}
	return &logical.Response{Data: state.toResponseData()}, nil
}

func (b *cloudflareBackend) pathSyncDeleteWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	ruleName := data.Get("name").(string)
	dryRun := data.Get("dry_run").(bool)
	confirmed := data.Get("delete_cloudflare_secrets").(bool)
	state, err := readSyncState(ctx, req.Storage, ruleName)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return &logical.Response{Data: map[string]interface{}{
			"rule_name": ruleName,
			"deleted":   []string{},
			"dry_run":   dryRun,
			"warnings":  []string{"no sync state found for rule"},
		}}, nil
	}
	if !dryRun && !confirmed {
		return logical.ErrorResponse("delete_cloudflare_secrets must be true to delete Cloudflare secrets"), nil
	}

	names := mapKeys(state.CloudflareNamesToID)
	respData := map[string]interface{}{
		"rule_name":        ruleName,
		"cloudflare_names": names,
		"deleted":          []string{},
		"dry_run":          dryRun,
		"warnings":         []string{},
	}
	if dryRun {
		respData["would_delete"] = names
		return &logical.Response{Data: respData}, nil
	}

	if state.CloudflareAccountID == "" || state.CloudflareStoreID == "" {
		return logical.ErrorResponse("sync state is missing Cloudflare account or store ID"), nil
	}
	cfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before deleting Cloudflare secrets"), nil
	}

	client := newCloudflareClient(cfg, b.httpClient)
	deleted := []string{}
	for _, name := range names {
		id := state.CloudflareNamesToID[name]
		if id == "" {
			continue
		}
		if err := client.deleteSecret(ctx, state.CloudflareAccountID, state.CloudflareStoreID, id); err != nil {
			return nil, err
		}
		deleted = append(deleted, name)
	}
	if err := req.Storage.Delete(ctx, syncStateStoragePrefix+ruleName); err != nil {
		return nil, err
	}
	respData["deleted"] = deleted
	return &logical.Response{Data: respData}, nil
}

func (b *cloudflareBackend) readKVv2Source(ctx context.Context, req *logical.Request, rule *syncRule) (sourceSecret, error) {
	system, ok := b.System().(logical.ExtendedSystemView)
	if !ok {
		return sourceSecret{}, fmt.Errorf("Vault system view does not support forwarded KV reads")
	}
	path := fmt.Sprintf("%s/data/%s", rule.VaultMount, rule.VaultPath)
	resp, err := system.ForwardGenericRequest(ctx, &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        path,
		ClientToken: req.ClientToken,
	})
	if err != nil {
		return sourceSecret{}, err
	}
	if resp == nil || resp.IsError() {
		if resp != nil && resp.IsError() {
			return sourceSecret{}, resp.Error()
		}
		return sourceSecret{}, fmt.Errorf("source secret %s not found", path)
	}
	data, ok := resp.Data["data"].(map[string]interface{})
	if !ok {
		return sourceSecret{}, fmt.Errorf("source secret %s did not return KV v2 data", path)
	}
	metadata, _ := resp.Data["metadata"].(map[string]interface{})
	version := intFromInterface(metadata["version"])

	if rule.VaultField != "" {
		value, ok := data[rule.VaultField]
		if !ok {
			return sourceSecret{}, fmt.Errorf("field %q not found in source secret", rule.VaultField)
		}
		return sourceSecret{Payload: []byte(fmt.Sprint(value)), Version: version}, nil
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return sourceSecret{}, err
	}
	return sourceSecret{Payload: payload, Version: version}, nil
}

func readSyncState(ctx context.Context, storage logical.Storage, name string) (*syncState, error) {
	entry, err := storage.Get(ctx, syncStateStoragePrefix+name)
	if err != nil || entry == nil {
		return nil, err
	}
	var state syncState
	if err := entry.DecodeJSON(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func deleteStaleRecordedSecrets(ctx context.Context, client *cloudflareClient, accountID, storeID string, oldNamesToIDs, newNamesToIDs map[string]string) ([]string, error) {
	deleted := []string{}
	for name, id := range oldNamesToIDs {
		if _, ok := newNamesToIDs[name]; ok || id == "" {
			continue
		}
		if err := client.deleteSecret(ctx, accountID, storeID, id); err != nil {
			return deleted, err
		}
		deleted = append(deleted, name)
	}
	sort.Strings(deleted)
	return deleted, nil
}

func writeSyncState(ctx context.Context, storage logical.Storage, name string, state *syncState) error {
	entry, err := logical.StorageEntryJSON(syncStateStoragePrefix+name, state)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (s *syncState) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"last_run_at":           s.LastRunAt,
		"last_success_at":       s.LastSuccessAt,
		"last_error":            s.LastError,
		"last_vault_version":    s.VaultVersion,
		"last_sha256":           s.SourceSHA256,
		"cloudflare_secret_ids": s.CloudflareNamesToID,
		"cloudflare_names":      mapKeys(s.CloudflareNamesToID),
		"cloudflare_account_id": s.CloudflareAccountID,
		"cloudflare_store_id":   s.CloudflareStoreID,
		"parts":                 s.Parts,
	}
}

func plannedNames(plan *syncPlan) []string {
	names := make([]string, 0, len(plan.Secrets))
	for _, secret := range plan.Secrets {
		names = append(names, secret.Name)
	}
	return names
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a = append([]string(nil), a...)
	b = append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func intFromInterface(value interface{}) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, _ := v.Int64()
		return int(i)
	default:
		return 0
	}
}
