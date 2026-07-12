package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// oidcEndpoints are the provider URLs the broker needs. They come from explicit
// config (tests, or a provider without discovery) or from the issuer's
// /.well-known/openid-configuration, fetched once and cached.
type oidcEndpoints struct {
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	UserInfo      string `json:"userinfo_endpoint"`
}

type oidcClient struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       string
	editorGroup  string
	hc           *http.Client

	// explicit overrides; when all set, discovery is skipped.
	override oidcEndpoints

	mu   sync.Mutex
	ep   *oidcEndpoints
	once bool
}

func (o *oidcClient) endpoints(ctx context.Context) (oidcEndpoints, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ep != nil {
		return *o.ep, nil
	}
	if o.override.Authorization != "" && o.override.Token != "" && o.override.UserInfo != "" {
		o.ep = &o.override
		return *o.ep, nil
	}
	discoURL := strings.TrimRight(o.issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoURL, nil)
	if err != nil {
		return oidcEndpoints{}, err
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		return oidcEndpoints{}, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcEndpoints{}, fmt.Errorf("oidc discovery: status %d", resp.StatusCode)
	}
	var ep oidcEndpoints
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&ep); err != nil {
		return oidcEndpoints{}, fmt.Errorf("oidc discovery: %w", err)
	}
	// Let explicit overrides win field-by-field (handy if a provider omits one).
	if o.override.Authorization != "" {
		ep.Authorization = o.override.Authorization
	}
	if o.override.Token != "" {
		ep.Token = o.override.Token
	}
	if o.override.UserInfo != "" {
		ep.UserInfo = o.override.UserInfo
	}
	if ep.Authorization == "" || ep.Token == "" || ep.UserInfo == "" {
		return oidcEndpoints{}, fmt.Errorf("oidc discovery: incomplete endpoints")
	}
	o.ep = &ep
	return ep, nil
}

// authRedirectURL builds the provider authorize URL for the given state.
func (o *oidcClient) authRedirectURL(ctx context.Context, state string) (string, error) {
	ep, err := o.endpoints(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", o.clientID)
	q.Set("redirect_uri", o.redirectURI)
	q.Set("scope", o.scopes)
	q.Set("state", state)
	q.Set("response_mode", "query")
	return ep.Authorization + "?" + q.Encode(), nil
}

// exchange swaps an authorization code for an access token, then reads the
// editor's identity from the userinfo endpoint. Returning claims from userinfo
// (rather than parsing the ID token) matches how Authelia's other clients here
// consume it and needs no JWKS verification: the response arrives directly from
// the issuer over authenticated TLS.
func (o *oidcClient) exchange(ctx context.Context, code string) (Editor, error) {
	ep, err := o.endpoints(ctx)
	if err != nil {
		return Editor{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", o.redirectURI)
	form.Set("client_id", o.clientID)
	form.Set("client_secret", o.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return Editor{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.hc.Do(req)
	if err != nil {
		return Editor{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return Editor{}, fmt.Errorf("token exchange: status %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return Editor{}, fmt.Errorf("token exchange: unparsable response")
	}
	if tok.Error != "" {
		return Editor{}, fmt.Errorf("token exchange: %s", tok.Error)
	}
	if tok.AccessToken == "" {
		return Editor{}, fmt.Errorf("token exchange: empty access token")
	}
	return o.userinfo(ctx, ep.UserInfo, tok.AccessToken)
}

func (o *oidcClient) userinfo(ctx context.Context, userInfoURL, accessToken string) (Editor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return Editor{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := o.hc.Do(req)
	if err != nil {
		return Editor{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return Editor{}, fmt.Errorf("userinfo: status %d", resp.StatusCode)
	}
	var claims struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Editor{}, fmt.Errorf("userinfo: unparsable response")
	}
	if claims.Email == "" {
		return Editor{}, fmt.Errorf("userinfo: no email claim")
	}
	if o.editorGroup != "" && !containsStr(claims.Groups, o.editorGroup) {
		return Editor{}, fmt.Errorf("not authorized: missing %q group", o.editorGroup)
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	if name == "" {
		name = claims.Email
	}
	return Editor{Sub: claims.Sub, Email: claims.Email, Name: name}, nil
}

func containsStr(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
