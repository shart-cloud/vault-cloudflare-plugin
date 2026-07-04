package plugin

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type managedSecretComment struct {
	Rule    string
	Vault   string
	Version int
	SHA256  string
	Part    string
}

func (b *cloudflareBackend) pathSyncReconcile() *framework.Path {
	return &framework.Path{
		Pattern: "sync/reconcile",
		Fields: map[string]*framework.FieldSchema{
			"dry_run": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Report drift without deleting orphaned Cloudflare entries.",
			},
			"delete_orphans": {
				Type:        framework.TypeBool,
				Description: "Delete managed Cloudflare secrets with no matching Vault rule. Requires dry_run=false.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathSyncReconcileWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathSyncReconcileWrite},
		},
		HelpSynopsis:    "Reconcile sync rules, plugin state, and Cloudflare metadata.",
		HelpDescription: "Reports missing Cloudflare entries, orphaned managed entries, stale comments or versions, and chunk drift.",
	}
}

func (b *cloudflareBackend) pathSyncReconcileWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dryRun := data.Get("dry_run").(bool)
	deleteOrphans := data.Get("delete_orphans").(bool)
	if deleteOrphans && dryRun {
		return logical.ErrorResponse("delete_orphans requires dry_run=false"), nil
	}

	cfCfg, err := readCloudflareConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfCfg == nil || cfCfg.APIToken == "" {
		return logical.ErrorResponse("config/cloudflare must be configured before reconciliation"), nil
	}
	syncCfg, err := readSyncConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if syncCfg == nil {
		syncCfg = defaultSyncConfig()
	}

	rules, err := readAllSyncRules(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	states, err := readAllSyncStates(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	rulesByName := map[string]*syncRule{}
	for _, rule := range rules {
		rulesByName[rule.Name] = rule
	}

	client := newCloudflareClient(cfCfg, b.httpClient)
	remoteCache := map[string][]cloudflareSecret{}
	remoteByScope := map[string]map[string]cloudflareSecret{}
	for name, state := range states {
		if state.CloudflareAccountID == "" || state.CloudflareStoreID == "" {
			continue
		}
		key := accountStoreKey(state.CloudflareAccountID, state.CloudflareStoreID)
		if _, ok := remoteCache[key]; !ok {
			remote, err := client.listSecrets(ctx, state.CloudflareAccountID, state.CloudflareStoreID)
			if err != nil {
				return nil, err
			}
			remoteCache[key] = remote
			remoteByScope[key] = secretsByName(remote)
		}
		_ = name
	}
	for _, rule := range rules {
		accountID := firstNonEmpty(rule.AccountID, cfCfg.AccountID)
		storeID := firstNonEmpty(rule.SecretsStoreID, cfCfg.SecretsStoreID)
		if accountID == "" || storeID == "" {
			continue
		}
		key := accountStoreKey(accountID, storeID)
		if _, ok := remoteCache[key]; !ok {
			remote, err := client.listSecrets(ctx, accountID, storeID)
			if err != nil {
				return nil, err
			}
			remoteCache[key] = remote
			remoteByScope[key] = secretsByName(remote)
		}
	}

	missing := []map[string]interface{}{}
	rulesWithoutState := []string{}
	stale := []map[string]interface{}{}
	chunkIssues := []map[string]interface{}{}
	orphans := []map[string]interface{}{}
	deletedOrphans := []string{}

	for _, rule := range rules {
		state := states[rule.Name]
		if state == nil {
			rulesWithoutState = append(rulesWithoutState, rule.Name)
			continue
		}
		key := accountStoreKey(state.CloudflareAccountID, state.CloudflareStoreID)
		remote := remoteByScope[key]
		for secretName, secretID := range state.CloudflareNamesToID {
			secret, ok := remote[secretName]
			if !ok {
				missing = append(missing, map[string]interface{}{"rule": rule.Name, "name": secretName, "id": secretID})
				continue
			}
			comment, ok := parseManagedComment(secret.Comment, syncCfg.ManagedCommentPrefix)
			if !ok || comment.Rule != rule.Name || comment.Version != state.VaultVersion || comment.SHA256 != state.SourceSHA256 {
				stale = append(stale, map[string]interface{}{"rule": rule.Name, "name": secretName, "comment": secret.Comment, "expected_version": state.VaultVersion, "expected_sha256": state.SourceSHA256})
			}
		}
		chunkIssues = append(chunkIssues, reconcileChunkState(rule.Name, state, remote)...)
	}

	for _, remote := range remoteCache {
		for _, secret := range remote {
			comment, ok := parseManagedComment(secret.Comment, syncCfg.ManagedCommentPrefix)
			if !ok {
				continue
			}
			state := states[comment.Rule]
			_, ruleExists := rulesByName[comment.Rule]
			if !ruleExists || state == nil || state.CloudflareNamesToID[secret.Name] == "" {
				entry := map[string]interface{}{"rule": comment.Rule, "name": secret.Name, "id": secret.ID}
				orphans = append(orphans, entry)
				if deleteOrphans && secret.ID != "" {
					accountID, storeID := findRemoteScope(secret.Name, secret.ID, remoteCache)
					if accountID != "" && storeID != "" {
						if err := client.deleteSecret(ctx, accountID, storeID, secret.ID); err != nil {
							return nil, err
						}
						deletedOrphans = append(deletedOrphans, secret.Name)
					}
				}
			}
		}
	}

	sort.Strings(rulesWithoutState)
	sort.Strings(deletedOrphans)
	return &logical.Response{Data: map[string]interface{}{
		"dry_run":                    dryRun,
		"missing_cloudflare_entries": missing,
		"rules_without_state":        rulesWithoutState,
		"managed_orphans":            orphans,
		"stale_comments_or_versions": stale,
		"chunk_issues":               chunkIssues,
		"deleted_orphans":            deletedOrphans,
	}}, nil
}

func readAllSyncStates(ctx context.Context, storage logical.Storage) (map[string]*syncState, error) {
	names, err := storage.List(ctx, syncStateStoragePrefix)
	if err != nil {
		return nil, err
	}
	states := make(map[string]*syncState, len(names))
	for _, name := range names {
		state, err := readSyncState(ctx, storage, name)
		if err != nil {
			return nil, err
		}
		if state != nil {
			states[name] = state
		}
	}
	return states, nil
}

func secretsByName(secrets []cloudflareSecret) map[string]cloudflareSecret {
	byName := make(map[string]cloudflareSecret, len(secrets))
	for _, secret := range secrets {
		byName[secret.Name] = secret
	}
	return byName
}

func parseManagedComment(comment, prefix string) (managedSecretComment, bool) {
	if !strings.HasPrefix(comment, prefix) {
		return managedSecretComment{}, false
	}
	parsed := managedSecretComment{}
	for _, field := range strings.Fields(comment) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "rule":
			parsed.Rule = value
		case "vault":
			parsed.Vault = value
		case "version":
			version, _ := strconv.Atoi(value)
			parsed.Version = version
		case "sha256":
			parsed.SHA256 = value
		case "part":
			parsed.Part = value
		}
	}
	return parsed, parsed.Rule != ""
}

func reconcileChunkState(ruleName string, state *syncState, remote map[string]cloudflareSecret) []map[string]interface{} {
	if state.Parts <= 1 {
		return nil
	}
	issues := []map[string]interface{}{}
	metaName := ""
	for name := range state.CloudflareNamesToID {
		if strings.HasSuffix(name, "__META") {
			metaName = name
			break
		}
	}
	if metaName == "" {
		issues = append(issues, map[string]interface{}{"rule": ruleName, "issue": "missing_recorded_meta"})
		return issues
	}
	base := strings.TrimSuffix(metaName, "__META")
	for i := 1; i <= state.Parts; i++ {
		name := fmt.Sprintf("%s__PART_%03d", base, i)
		if state.CloudflareNamesToID[name] == "" {
			issues = append(issues, map[string]interface{}{"rule": ruleName, "issue": "missing_recorded_part", "name": name})
			continue
		}
		if _, ok := remote[name]; !ok {
			issues = append(issues, map[string]interface{}{"rule": ruleName, "issue": "missing_remote_part", "name": name})
		}
	}
	for name := range remote {
		if strings.HasPrefix(name, base+"__PART_") && state.CloudflareNamesToID[name] == "" {
			issues = append(issues, map[string]interface{}{"rule": ruleName, "issue": "extra_remote_part", "name": name})
		}
	}
	return issues
}

func accountStoreKey(accountID, storeID string) string {
	return accountID + "\x00" + storeID
}

func findRemoteScope(name, id string, remoteCache map[string][]cloudflareSecret) (string, string) {
	for key, secrets := range remoteCache {
		for _, secret := range secrets {
			if secret.Name == name && secret.ID == id {
				accountID, storeID, _ := strings.Cut(key, "\x00")
				return accountID, storeID
			}
		}
	}
	return "", ""
}
