package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The agent API end to end, through the real handler chain: tokens, the
// server-sealed path, MCP, OAuth, and `pyxis share`. Every share made here is
// opened again with nothing but its link, the way a recipient's browser would,
// so a format slip shows up as a failed decryption rather than a passing test.
//
// Runs only with TEST_DATABASE_URL pointing at a throwaway database.

func newAPITestServer(t *testing.T) (*App, *httptest.Server, *User, context.Context) {
	t.Helper()
	a, ctx := newQuotaTestApp(t)
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	a.tmpl = tmpl
	a.filesDir = t.TempDir()
	a.unlockKey = randomBytes(32)
	a.sealMaxBytes = 8 << 20
	a.setMaxUploadDefault(16 << 20)
	a.loginLimiter = newFailLimiter(failMaxTries, failWindow)
	a.loginSourceLimiter = newFailLimiter(failMaxPerSource, failWindow)
	a.shareLimiter = newFailLimiter(failMaxTries, failWindow)
	a.apiLimiter = newFailLimiter(failMaxPerSource, failWindow)
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	a.publicURL = srv.URL
	user := mkUser(t, a, ctx, "agent-"+randomToken(4), false)
	return a, srv, user, ctx
}

func apiDo(t *testing.T, method, u, token, ctype string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

type openedFile struct {
	Name, Type string
	Data       []byte
}

// openShare does what app.js does with a batch link: derive the keys from the
// fragment, check the sealed roster against the listing, open every name,
// unwrap every key and decrypt every member.
func openShare(t *testing.T, link string) []openedFile {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Fragment == "" {
		t.Fatalf("link %q has no key fragment", link)
	}
	secret, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := deriveShareKeys(secret)
	if err != nil {
		t.Fatal(err)
	}
	base := u.Scheme + "://" + u.Host + u.Path
	resp, body := apiDo(t, http.MethodGet, base+"/manifest", "", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manifest: %d %s", resp.StatusCode, body)
	}
	var listing struct {
		ID    string `json:"id"`
		Files []struct {
			ID, EncName, WrappedKey, Manifest string
		} `json:"files"`
		Roster string `json:"roster"`
	}
	if err := json.Unmarshal(body, &listing); err != nil {
		t.Fatal(err)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	open := func(aead interface {
		Open(dst, nonce, ct, aad []byte) ([]byte, error)
	}, blob, aad []byte) []byte {
		out, err := aead.Open(nil, blob[:12], blob[12:], aad)
		if err != nil {
			t.Fatalf("a sealed blob does not open under the link's key: %v", err)
		}
		return out
	}

	var roster rosterBody
	if err := json.Unmarshal(open(keys.roster, dec(listing.Roster), []byte(sealRosterAADPrefix+listing.ID)), &roster); err != nil {
		t.Fatal(err)
	}
	if roster.Batch != listing.ID || len(roster.Files) != len(listing.Files) {
		t.Fatalf("roster names %d file(s) of batch %s; listing has %d of %s",
			len(roster.Files), roster.Batch, len(listing.Files), listing.ID)
	}

	var out []openedFile
	for i, f := range listing.Files {
		manifest := dec(f.Manifest)
		var m v5Manifest
		if err := json.Unmarshal(manifest, &m); err != nil {
			t.Fatal(err)
		}
		body := open(keys.name, dec(f.EncName), []byte(sealNameAADPrefix+m.ID))
		n := binary.BigEndian.Uint16(body)
		var name sealedNameBody
		if err := json.Unmarshal(body[2:2+n], &name); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(manifest)
		e := roster.Files[i]
		if e.ID != f.ID || e.Name != name.Name || e.Size != m.Size || e.Type != name.Type ||
			e.Manifest != base64.RawURLEncoding.EncodeToString(sum[:]) || m.Batch != listing.ID {
			t.Fatalf("member %d does not match its roster entry: %+v vs %+v", i, e, name)
		}
		fileKey := open(keys.wrap, dec(f.WrappedKey), nil)
		resp, ct := apiDo(t, http.MethodGet, base+"/f/"+f.ID+"/raw", "", "", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("raw: %d", resp.StatusCode)
		}
		head := buildContainerHeader(manifest, e2eVersionV5)
		if !bytes.HasPrefix(ct, head) {
			t.Fatal("stored object does not begin with its v5 header")
		}
		aead, _ := newAEAD(fileKey)
		var plain []byte
		rest := ct[len(head):]
		for idx := int64(0); idx < m.Chunks; idx++ {
			l := min(len(rest), chunkPlainSize+gcmOverhead)
			nonce := make([]byte, 12)
			binary.BigEndian.PutUint64(nonce[4:], uint64(idx))
			p, err := aead.Open(nil, nonce, rest[:l], manifest)
			if err != nil {
				t.Fatalf("chunk %d: %v", idx, err)
			}
			plain = append(plain, p...)
			rest = rest[l:]
		}
		if len(rest) != 0 || int64(len(plain)) != m.Size {
			t.Fatal("container geometry is off")
		}
		out = append(out, openedFile{Name: name.Name, Type: name.Type, Data: plain})
	}
	return out
}

func TestAPIServerSealedShare(t *testing.T) {
	a, srv, user, ctx := newAPITestServer(t)
	token, err := a.createAPIToken(ctx, user.ID, "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// No token, a wrong token, and a session cookie are all refused.
	resp, _ := apiDo(t, http.MethodGet, srv.URL+"/api/v1", "", "", nil)
	if resp.StatusCode != http.StatusUnauthorized ||
		!strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("no token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp, _ := apiDo(t, http.MethodGet, srv.URL+"/api/v1", "pyx_nope", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	sid, _, err := a.createSession(ctx, user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	if r2, err := http.DefaultClient.Do(req); err != nil || r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a session cookie must not authenticate the API")
	}

	// JSON: text and binary in one link.
	binary := []byte{0, 1, 2, 0xff, 'P', 'N', 'G'}
	payload, _ := json.Marshal(map[string]any{"files": []map[string]any{
		{"name": "notes.md", "text": "# hello\n"},
		{"name": "../../etc/pic.bin", "content_base64": base64.StdEncoding.EncodeToString(binary)},
	}})
	resp, body := apiDo(t, http.MethodPost, srv.URL+"/api/v1/shares", token, "application/json", bytes.NewReader(payload))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var res sharedResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.URL, srv.URL+"/b/"+res.ID+"#") || !res.ServerSealed {
		t.Fatalf("result: %+v", res)
	}
	if res.ExpiresAt == nil || time.Until(*res.ExpiresAt) > 24*time.Hour || time.Until(*res.ExpiresAt) < 23*time.Hour {
		t.Fatalf("default expiry should be one day, got %v", res.ExpiresAt)
	}
	files := openShare(t, res.URL)
	if len(files) != 2 || string(files[0].Data) != "# hello\n" || files[0].Name != "notes.md" ||
		!bytes.Equal(files[1].Data, binary) || files[1].Name != "pic.bin" {
		t.Fatalf("opened: %+v", files)
	}

	// Nothing on disk is plaintext, and the key is nowhere in the database.
	frag := res.URL[strings.Index(res.URL, "#")+1:]
	entries, _ := os.ReadDir(a.filesDir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(a.filesDir, e.Name()))
		if bytes.Contains(b, []byte("# hello")) {
			t.Fatal("plaintext on disk")
		}
	}
	var hits int
	if err := a.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM batches WHERE id = $1 AND (encode(roster,'escape') LIKE '%'||$2||'%')`,
		res.ID, frag).Scan(&hits); err != nil || hits != 0 {
		t.Fatalf("key material in the batch row (%d, %v)", hits, err)
	}

	// The download page states it was not end-to-end encrypted.
	resp, page := apiDo(t, http.MethodGet, srv.URL+"/b/"+res.ID, "", "", nil)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(page, []byte("sealed-note")) ||
		bytes.Contains(page, []byte(`class="e2e-badge"`)) {
		t.Fatalf("landing page does not flag the server-sealed share (%d)", resp.StatusCode)
	}

	// Multipart and a raw body, with explicit terms.
	var mp bytes.Buffer
	mp.WriteString("--X\r\nContent-Disposition: form-data; name=\"expires_hours\"\r\n\r\n2\r\n" +
		"--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nAAA\r\n--X--\r\n")
	resp, body = apiDo(t, http.MethodPost, srv.URL+"/api/v1/shares", token, "multipart/form-data; boundary=X", &mp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("multipart: %d %s", resp.StatusCode, body)
	}
	_ = json.Unmarshal(body, &res)
	if time.Until(*res.ExpiresAt) > 2*time.Hour {
		t.Fatal("expires_hours ignored")
	}
	if f := openShare(t, res.URL); string(f[0].Data) != "AAA" || f[0].Name != "a.txt" {
		t.Fatalf("multipart opened: %+v", f)
	}
	resp, body = apiDo(t, http.MethodPost, srv.URL+"/api/v1/shares?name=raw.json&max_downloads=5", token,
		"application/json; charset=utf-8", strings.NewReader(`{"files":[{"name":"x.txt","text":"via json"}]}`))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("json with charset: %d %s", resp.StatusCode, body)
	}
	resp, body = apiDo(t, http.MethodPost, srv.URL+"/api/v1/shares?name=raw.csv&max_downloads=5", token,
		"text/csv", strings.NewReader("a,b\n1,2\n"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("raw: %d %s", resp.StatusCode, body)
	}
	_ = json.Unmarshal(body, &res)
	if res.MaxDownloads == nil || *res.MaxDownloads != 5 {
		t.Fatal("max_downloads ignored")
	}

	// Over the server-sealing limit: refused, and nothing is left behind.
	before, _ := os.ReadDir(a.filesDir)
	big := bytes.Repeat([]byte("x"), int(a.sealMaxBytes)+10)
	resp, _ = apiDo(t, http.MethodPost, srv.URL+"/api/v1/shares?name=big.bin", token, "application/octet-stream", bytes.NewReader(big))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", resp.StatusCode)
	}
	if after, _ := os.ReadDir(a.filesDir); len(after) != len(before) {
		t.Fatal("a refused share left blobs behind")
	}

	// List and revoke.
	resp, body = apiDo(t, http.MethodGet, srv.URL+"/api/v1/shares", token, "", nil)
	var list struct{ Shares []apiShareRow }
	_ = json.Unmarshal(body, &list)
	if resp.StatusCode != http.StatusOK || len(list.Shares) != 4 {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	resp, _ = apiDo(t, http.MethodDelete, srv.URL+"/api/v1/shares/"+res.ID, token, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if resp, _ := apiDo(t, http.MethodGet, srv.URL+"/b/"+res.ID+"/manifest", "", "", nil); resp.StatusCode != http.StatusGone {
		t.Fatalf("revoked share still served: %d", resp.StatusCode)
	}
	other := mkUser(t, a, ctx, "other-"+randomToken(4), false)
	otherTok, _ := a.createAPIToken(ctx, other.ID, "o", nil)
	if resp, _ := apiDo(t, http.MethodDelete, srv.URL+"/api/v1/shares/"+list.Shares[1].ID, otherTok, "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another user revoked a share: %d", resp.StatusCode)
	}
}

func mcpCall(t *testing.T, srv *httptest.Server, token, method string, params any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp, body := apiDo(t, http.MethodPost, srv.URL+"/mcp", token, "application/json", bytes.NewReader(b))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", method, resp.StatusCode, body)
	}
	var out struct {
		Result map[string]any
		Error  *mcpError
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Error != nil {
		t.Fatalf("%s: %s", method, body)
	}
	return out.Result
}

func TestMCPShare(t *testing.T) {
	a, srv, user, ctx := newAPITestServer(t)
	token, _ := a.createAPIToken(ctx, user.ID, "mcp", nil)

	init := mcpCall(t, srv, token, "initialize", map[string]any{"protocolVersion": "2025-03-26"})
	if init["protocolVersion"] != "2025-03-26" {
		t.Fatalf("initialize: %v", init)
	}
	if resp, _ := apiDo(t, http.MethodPost, srv.URL+"/mcp", token, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification: %d", resp.StatusCode)
	}
	tools := mcpCall(t, srv, token, "tools/list", nil)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools: %v", tools)
	}

	res := mcpCall(t, srv, token, "tools/call", map[string]any{"name": "share_text",
		"arguments": map[string]any{"text": "from an agent", "name": "answer.txt", "expires_hours": 3}})
	if res["isError"] != false {
		t.Fatalf("share_text: %v", res)
	}
	link := res["structuredContent"].(map[string]any)["url"].(string)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, link) {
		t.Fatal("the tool text must carry the full link")
	}
	if f := openShare(t, link); string(f[0].Data) != "from an agent" || f[0].Type != "text/plain; charset=utf-8" {
		t.Fatalf("opened: %+v", f)
	}

	res = mcpCall(t, srv, token, "tools/call", map[string]any{"name": "share_files",
		"arguments": map[string]any{"files": []any{map[string]any{"name": "x.bin"}}}})
	if res["isError"] != true {
		t.Fatal("a file without content must be a tool error")
	}

	id := strings.TrimPrefix(strings.SplitN(link, "#", 2)[0], srv.URL+"/b/")
	res = mcpCall(t, srv, token, "tools/call", map[string]any{"name": "delete_share", "arguments": map[string]any{"id": id}})
	if res["isError"] != false {
		t.Fatalf("delete_share: %v", res)
	}
	res = mcpCall(t, srv, token, "tools/call", map[string]any{"name": "list_shares"})
	if !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "expired or revoked") {
		t.Fatalf("list_shares: %v", res)
	}
}

func TestOAuthFlow(t *testing.T) {
	a, srv, user, ctx := newAPITestServer(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Discovery from a bare 401.
	resp, body := apiDo(t, http.MethodGet, srv.URL+"/.well-known/oauth-authorization-server", "", "", nil)
	var meta map[string]any
	_ = json.Unmarshal(body, &meta)
	if resp.StatusCode != http.StatusOK || meta["token_endpoint"] != srv.URL+"/oauth/token" {
		t.Fatalf("metadata: %s", body)
	}

	// Dynamic registration, cross-origin as a browser-based client would.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/register", strings.NewReader(
		`{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"none"}`))
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Content-Type", "application/json")
	r2, err := http.DefaultClient.Do(req)
	if err != nil || r2.StatusCode != http.StatusCreated {
		t.Fatalf("register: %v %v", r2.StatusCode, err)
	}
	var client struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(r2.Body).Decode(&client)
	r2.Body.Close()
	t.Cleanup(func() {
		_, _ = a.db.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, client.ClientID)
	})

	verifier := randomToken(40)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID},
		"redirect_uri":   {"https://claude.ai/api/mcp/auth_callback"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"st8"}, "resource": {srv.URL + "/mcp"},
	}

	// Without a session the consent page sends the browser to sign in.
	r3, _ := noRedirect.Get(srv.URL + "/oauth/authorize?" + q.Encode())
	if r3.StatusCode != http.StatusSeeOther || !strings.HasPrefix(r3.Header.Get("Location"), "/login?next=") {
		t.Fatalf("authorize without session: %d %s", r3.StatusCode, r3.Header.Get("Location"))
	}

	sid, _, _ := a.createSession(ctx, user.ID, nil)
	cookie := &http.Cookie{Name: sessionCookieName, Value: sid}
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(cookie)
	r4, _ := noRedirect.Do(req)
	page, _ := io.ReadAll(r4.Body)
	r4.Body.Close()
	if r4.StatusCode != http.StatusOK || !strings.Contains(r4.Header.Get("Content-Security-Policy"), "form-action 'self' https://claude.ai") ||
		!bytes.Contains(page, []byte(client.ClientID)) {
		t.Fatalf("consent page: %d %q", r4.StatusCode, r4.Header.Get("Content-Security-Policy"))
	}

	approve := func() string {
		form := url.Values{}
		for k, v := range q {
			form[k] = v
		}
		form.Set("decision", "approve")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", srv.URL)
		req.AddCookie(cookie)
		r, _ := noRedirect.Do(req)
		loc, _ := url.Parse(r.Header.Get("Location"))
		if r.StatusCode != http.StatusSeeOther || loc.Host != "claude.ai" || loc.Query().Get("state") != "st8" ||
			loc.Query().Get("iss") != srv.URL {
			t.Fatalf("approve: %d %s", r.StatusCode, loc)
		}
		return loc.Query().Get("code")
	}
	code := approve()

	tokenReq := func(form url.Values) (int, map[string]any) {
		resp, body := apiDo(t, http.MethodPost, srv.URL+"/oauth/token", "", "application/x-www-form-urlencoded",
			strings.NewReader(form.Encode()))
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		return resp.StatusCode, out
	}
	exchange := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {client.ClientID},
		"redirect_uri": {"https://claude.ai/api/mcp/auth_callback"}, "code_verifier": {verifier}}
	if st, _ := tokenReq(url.Values{"grant_type": {"authorization_code"}, "code": {approve()},
		"client_id": {client.ClientID}, "code_verifier": {randomToken(40)}}); st != http.StatusBadRequest {
		t.Fatalf("a wrong verifier was accepted: %d", st)
	}
	st, tok := tokenReq(exchange)
	if st != http.StatusOK || tok["access_token"] == nil {
		t.Fatalf("exchange: %d %v", st, tok)
	}
	if st, _ := tokenReq(exchange); st != http.StatusBadRequest {
		t.Fatal("a code was accepted twice")
	}

	// The access token works on /mcp and makes a share like any other token.
	access := tok["access_token"].(string)
	res := mcpCall(t, srv, access, "tools/call", map[string]any{"name": "share_text", "arguments": map[string]any{"text": "oauth"}})
	if f := openShare(t, res["structuredContent"].(map[string]any)["url"].(string)); string(f[0].Data) != "oauth" {
		t.Fatal("share made with an OAuth token does not open")
	}

	// Refresh rotates: the old refresh token is spent.
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)},
		"client_id": {client.ClientID}}
	if st, t2 := tokenReq(refresh); st != http.StatusOK || t2["access_token"] == access {
		t.Fatalf("refresh: %d %v", st, t2)
	}
	if st, _ := tokenReq(refresh); st != http.StatusBadRequest {
		t.Fatal("a refresh token was accepted twice")
	}

	// The account page lists the app, and disconnecting kills its tokens.
	grants, _ := a.listOAuthGrants(ctx, user.ID.String())
	if len(grants) != 1 || grants[0].ClientName != "Claude" {
		t.Fatalf("grants: %+v", grants)
	}
	tokens, _ := a.listAPITokens(ctx, user.ID)
	if len(tokens) != 0 {
		t.Fatal("OAuth access tokens must not crowd the token list")
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/account/apps/"+client.ClientID+"/disconnect", nil)
	req.AddCookie(cookie)
	if r, _ := noRedirect.Do(req); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("disconnect: %d", r.StatusCode)
	}
	if resp, _ := apiDo(t, http.MethodGet, srv.URL+"/api/v1", access, "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("a disconnected app's token still works")
	}
}

// TestShareCLI runs `pyxis share` against the server: encrypted on this side,
// ciphertext only across the wire, and an ordinary end-to-end share at the end.
func TestShareCLI(t *testing.T) {
	a, srv, user, ctx := newAPITestServer(t)
	token, _ := a.createAPIToken(ctx, user.ID, "cli", nil)
	dir := t.TempDir()
	big := bytes.Repeat([]byte("0123456789abcdef"), 3*chunkPlainSize/16+77)
	paths := []string{filepath.Join(dir, "report.pdf"), filepath.Join(dir, "empty.txt")}
	_ = os.WriteFile(paths[0], big, 0o600)
	_ = os.WriteFile(paths[1], nil, 0o600)

	c := &shareClient{base: srv.URL, token: token, http: srv.Client()}
	res, err := c.share(paths, 24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	files := openShare(t, res.URL)
	if len(files) != 2 || !bytes.Equal(files[0].Data, big) || files[0].Type != "application/pdf" ||
		files[1].Name != "empty.txt" || len(files[1].Data) != 0 {
		t.Fatalf("opened: %d file(s)", len(files))
	}
	var sealed bool
	if err := a.db.QueryRow(ctx, `SELECT server_sealed FROM batches WHERE id = $1`, res.ID).Scan(&sealed); err != nil || sealed {
		t.Fatal("a client-sealed share must not be marked server-sealed")
	}
	if res.ExpiresAt == nil {
		t.Fatal("the CLI's share has no expiry")
	}
}

// TestRedirectRegistered pins RFC 8252 §7.3: a loopback redirect may come back
// on another port than the one registered, and nothing else may differ.
func TestRedirectRegistered(t *testing.T) {
	reg := []string{"http://localhost:53438/callback", "https://claude.ai/api/mcp/auth_callback"}
	for uri, want := range map[string]bool{
		"http://localhost:53438/callback":              true,
		"http://localhost:61000/callback":              true,
		"http://localhost/callback":                    true,
		"https://claude.ai/api/mcp/auth_callback":      true,
		"http://localhost:61000/other":                 false,
		"http://127.0.0.1:61000/callback":              false,
		"https://localhost:61000/callback":             false,
		"http://evil.example:53438/callback":           false,
		"https://claude.ai:8443/api/mcp/auth_callback": false,
		"http://localhost:61000/callback?x=1":          false,
	} {
		if got := redirectRegistered(reg, uri); got != want {
			t.Errorf("%s: got %v, want %v", uri, got, want)
		}
	}
}

// TestUnwrapParams: a link copied out of a wrapped terminal line still works,
// and the client's state is returned untouched.
func TestUnwrapParams(t *testing.T) {
	q := unwrapParams(url.Values{
		"redirect_uri":   {"http:  //localhost:53438/call back"},
		"client_id":      {"pxc_ab cd"},
		"code_challenge": {"abc\n def"},
		"state":          {"a b"},
	})
	if q.Get("redirect_uri") != "http://localhost:53438/callback" || q.Get("client_id") != "pxc_abcd" ||
		q.Get("code_challenge") != "abcdef" || q.Get("state") != "a b" {
		t.Fatalf("unwrapped: %v", q)
	}
}
