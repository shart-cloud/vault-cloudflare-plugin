package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type cloudflareClient struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client
}

type cloudflareSecret struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Scopes  []string `json:"scopes,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

type cloudflareSecretWrite struct {
	Name    string   `json:"name,omitempty"`
	Value   string   `json:"value"`
	Scopes  []string `json:"scopes"`
	Comment string   `json:"comment,omitempty"`
}

type cloudflarePermissionGroup struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

type cloudflareAPITokenPolicy struct {
	Effect           string                 `json:"effect"`
	PermissionGroups []map[string]string    `json:"permission_groups"`
	Resources        map[string]interface{} `json:"resources"`
}

type cloudflareAPITokenCondition struct {
	RequestIP *cloudflareAPITokenIPCondition `json:"request_ip,omitempty"`
}

type cloudflareAPITokenIPCondition struct {
	In    []string `json:"in,omitempty"`
	NotIn []string `json:"not_in,omitempty"`
}

type cloudflareAPITokenCreateRequest struct {
	Name      string                       `json:"name"`
	Policies  []cloudflareAPITokenPolicy   `json:"policies"`
	Condition *cloudflareAPITokenCondition `json:"condition,omitempty"`
	NotBefore string                       `json:"not_before,omitempty"`
	ExpiresOn string                       `json:"expires_on"`
}

type cloudflareAPIToken struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	ExpiresOn string `json:"expires_on,omitempty"`
}

type cloudflareEnvelope[T any] struct {
	Success bool    `json:"success"`
	Result  T       `json:"result"`
	Errors  []cfErr `json:"errors"`
}

type cfErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudflareEnvelopeStatus struct {
	Success bool    `json:"success"`
	Errors  []cfErr `json:"errors"`
}

func newCloudflareClient(cfg *cloudflareConfig, httpClient *http.Client) *cloudflareClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &cloudflareClient{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		apiToken:   cfg.APIToken,
		httpClient: httpClient,
	}
}

func (c *cloudflareClient) listSecrets(ctx context.Context, accountID, storeID string) ([]cloudflareSecret, error) {
	path := fmt.Sprintf("/accounts/%s/secrets_store/stores/%s/secrets", url.PathEscape(accountID), url.PathEscape(storeID))
	var out cloudflareEnvelope[[]cloudflareSecret]
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (c *cloudflareClient) createSecret(ctx context.Context, accountID, storeID string, secret cloudflareSecretWrite) (cloudflareSecret, error) {
	path := fmt.Sprintf("/accounts/%s/secrets_store/stores/%s/secrets", url.PathEscape(accountID), url.PathEscape(storeID))
	var out cloudflareEnvelope[cloudflareSecret]
	if err := c.do(ctx, http.MethodPost, path, secret, &out); err != nil {
		return cloudflareSecret{}, err
	}
	return out.Result, nil
}

func (c *cloudflareClient) patchSecret(ctx context.Context, accountID, storeID, secretID string, secret cloudflareSecretWrite) (cloudflareSecret, error) {
	path := fmt.Sprintf("/accounts/%s/secrets_store/stores/%s/secrets/%s", url.PathEscape(accountID), url.PathEscape(storeID), url.PathEscape(secretID))
	var out cloudflareEnvelope[cloudflareSecret]
	if err := c.do(ctx, http.MethodPatch, path, secret, &out); err != nil {
		return cloudflareSecret{}, err
	}
	return out.Result, nil
}

func (c *cloudflareClient) deleteSecret(ctx context.Context, accountID, storeID, secretID string) error {
	path := fmt.Sprintf("/accounts/%s/secrets_store/stores/%s/secrets/%s", url.PathEscape(accountID), url.PathEscape(storeID), url.PathEscape(secretID))
	var out cloudflareEnvelope[json.RawMessage]
	return c.doAllowNotFound(ctx, http.MethodDelete, path, nil, &out)
}

func (c *cloudflareClient) listPermissionGroups(ctx context.Context, accountID string) ([]cloudflarePermissionGroup, error) {
	path := fmt.Sprintf("/accounts/%s/tokens/permission_groups", url.PathEscape(accountID))
	var out cloudflareEnvelope[[]cloudflarePermissionGroup]
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (c *cloudflareClient) createAccountToken(ctx context.Context, accountID string, request cloudflareAPITokenCreateRequest) (cloudflareAPIToken, error) {
	path := fmt.Sprintf("/accounts/%s/tokens", url.PathEscape(accountID))
	var out cloudflareEnvelope[cloudflareAPIToken]
	if err := c.do(ctx, http.MethodPost, path, request, &out); err != nil {
		return cloudflareAPIToken{}, err
	}
	return out.Result, nil
}

func (c *cloudflareClient) listAccountTokens(ctx context.Context, accountID string) ([]cloudflareAPIToken, error) {
	path := fmt.Sprintf("/accounts/%s/tokens", url.PathEscape(accountID))
	var out cloudflareEnvelope[[]cloudflareAPIToken]
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (c *cloudflareClient) deleteAccountToken(ctx context.Context, accountID, tokenID string) error {
	path := fmt.Sprintf("/accounts/%s/tokens/%s", url.PathEscape(accountID), url.PathEscape(tokenID))
	var out cloudflareEnvelope[json.RawMessage]
	return c.doAllowNotFound(ctx, http.MethodDelete, path, nil, &out)
}

func (c *cloudflareClient) do(ctx context.Context, method, path string, in, out any) error {
	return c.doStatus(ctx, method, path, in, out, false)
}

func (c *cloudflareClient) doAllowNotFound(ctx context.Context, method, path string, in, out any) error {
	return c.doStatus(ctx, method, path, in, out, true)
}

func (c *cloudflareClient) doStatus(ctx context.Context, method, path string, in, out any, allowNotFound bool) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if allowNotFound && resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare API returned %s", resp.Status)
	}
	var status cloudflareEnvelopeStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return err
	}
	if !status.Success {
		return fmt.Errorf("cloudflare API returned success=false: %s", formatCloudflareErrors(status.Errors))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return err
	}
	return nil
}

func formatCloudflareErrors(errors []cfErr) string {
	if len(errors) == 0 {
		return "no error details"
	}
	parts := make([]string, 0, len(errors))
	for _, err := range errors {
		parts = append(parts, fmt.Sprintf("%d %s", err.Code, err.Message))
	}
	return strings.Join(parts, "; ")
}
