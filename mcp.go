package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// /mcp — the Model Context Protocol, Streamable HTTP transport, for AI agents.
//
// Only what sharing needs: JSON-RPC over POST, one message per request, plain
// JSON responses (no SSE stream, so GET is refused as the spec allows), and the
// same bearer token as /api/v1.
//
// An MCP client has no way to encrypt anything itself — a tool call is JSON
// the model writes — so every share made here is SERVER-sealed: the plaintext
// passes through this process, is encrypted in memory and dropped, and the key
// exists only in the link the tool returns. The tool descriptions say so, so
// the agent can say so too, and the download page says it to the recipient.

var mcpProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
)

func (a *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "this MCP endpoint answers POST only (no SSE stream)", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.sealMaxBytes/3*4+1<<20)
	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		msg := "parse error"
		if errors.As(err, &tooBig) {
			msg = fmt.Sprintf("request too large: a share made through MCP holds at most %s",
				humanSize(a.sealMaxBytes))
		}
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: json.RawMessage("null"),
			Error: &mcpError{Code: rpcParseError, Message: msg}})
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeJSON(w, http.StatusOK, mcpResponse{JSONRPC: "2.0", ID: nullID(req.ID),
			Error: &mcpError{Code: rpcInvalidRequest, Message: "not a JSON-RPC 2.0 request"}})
		return
	}
	// A notification (no id) gets no answer beyond the transport's.
	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp := mcpResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := mcpProtocolVersions[0]
		for _, v := range mcpProtocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		resp.Result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "pyxis", "version": "1"},
			"instructions": "Pyxis shares files through links that expire (after 24 hours unless you ask " +
				"otherwise). Every share tool returns a url; give the user that url EXACTLY and in full — " +
				"the part after # is the only copy of the decryption key, and Pyxis cannot recover it. " +
				"Shares made here are encrypted by the Pyxis server, not end-to-end in the sender's " +
				"browser; the download page tells the recipient so.",
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &mcpError{Code: rpcInvalidParams, Message: "invalid params"}
			break
		}
		result, rpcErr := a.callMCPTool(r, p.Name, p.Arguments)
		resp.Result, resp.Error = result, rpcErr
	default:
		resp.Error = &mcpError{Code: rpcMethodNotFound, Message: "method not found: " + req.Method}
	}
	writeJSON(w, http.StatusOK, resp)
}

func nullID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func mcpTools() []map[string]any {
	terms := map[string]any{
		"expires_hours": map[string]any{"type": "integer", "minimum": 0, "maximum": 8760,
			"description": "Hours until the link stops working. Default 24. 0 means never — only if the user asks for that."},
		"max_downloads": map[string]any{"type": "integer", "minimum": 0,
			"description": "Retire the link after this many file downloads. Omit or 0 for no limit."},
	}
	with := func(props map[string]any) map[string]any {
		for k, v := range terms {
			props[k] = v
		}
		return props
	}
	file := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":           map[string]any{"type": "string", "description": "File name shown to the recipient, e.g. report.pdf."},
			"text":           map[string]any{"type": "string", "description": "The content as text (UTF-8). Use this OR content_base64."},
			"content_base64": map[string]any{"type": "string", "description": "The content as standard base64, for binary files."},
			"content_type":   map[string]any{"type": "string", "description": "MIME type. Guessed from the name if omitted."},
		},
		"required": []string{"name"},
	}
	linkNote := " Returns the full share URL: give it to the user verbatim, including everything after #, " +
		"which is the decryption key and exists nowhere else."
	return []map[string]any{
		{
			"name":        "share_files",
			"title":       "Share files",
			"description": "Upload one or more files to Pyxis under a single share link that expires after 24 hours by default." + linkNote,
			"inputSchema": map[string]any{
				"type": "object",
				"properties": with(map[string]any{
					"files": map[string]any{"type": "array", "items": file, "minItems": 1},
				}),
				"required": []string{"files"},
			},
		},
		{
			"name":        "share_text",
			"title":       "Share text",
			"description": "Share a piece of text (notes, code, a log, Markdown) as a file on Pyxis, expiring after 24 hours by default." + linkNote,
			"inputSchema": map[string]any{
				"type": "object",
				"properties": with(map[string]any{
					"text": map[string]any{"type": "string"},
					"name": map[string]any{"type": "string", "description": "File name, default text.txt."},
				}),
				"required": []string{"text"},
			},
		},
		{
			"name":        "list_shares",
			"title":       "List shares",
			"description": "List the shares made through the Pyxis API with this account: id, expiry, file count, whether still active. The decryption keys are not stored, so the listed URLs cannot open the files.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			"annotations": map[string]any{"readOnlyHint": true},
		},
		{
			"name":        "delete_share",
			"title":       "Revoke a share",
			"description": "Revoke a share now: its link stops working and the stored files are deleted.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"id": map[string]any{"type": "string", "description": "The share id."}},
				"required":   []string{"id"},
			},
			"annotations": map[string]any{"destructiveHint": true},
		},
	}
}

// toolText is a tool result: text for the model, structured for the client.
func toolText(text string, structured any, isError bool) map[string]any {
	res := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
	if structured != nil {
		res["structuredContent"] = structured
	}
	return res
}

func (a *App) callMCPTool(r *http.Request, name string, args json.RawMessage) (any, *mcpError) {
	user := userFromContext(r.Context())
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	switch name {
	case "share_files", "share_text":
		var req shareRequestJSON
		if name == "share_text" {
			var t struct {
				Text         *string      `json:"text"`
				Name         string       `json:"name"`
				ExpiresHours *json.Number `json:"expires_hours"`
				MaxDownloads *json.Number `json:"max_downloads"`
			}
			if err := decodeArgs(args, &t); err != nil || t.Text == nil {
				return nil, &mcpError{Code: rpcInvalidParams, Message: "text is required"}
			}
			if t.Name == "" {
				t.Name = "text.txt"
			}
			req = shareRequestJSON{Files: []shareFileJSON{{Name: t.Name, Text: t.Text}},
				ExpiresHours: t.ExpiresHours, MaxDownloads: t.MaxDownloads}
		} else if err := decodeArgs(args, &req); err != nil {
			return nil, &mcpError{Code: rpcInvalidParams, Message: "invalid arguments: " + err.Error()}
		}
		files, err := decodeJSONFiles(req.Files, a.sealMaxBytes)
		defer wipeFiles(files)
		if err == nil {
			var res *sharedResult
			res, err = a.sealShare(r.Context(), r, user, req.options(), files)
			if err == nil {
				return toolText(describeShare(res), res, false), nil
			}
		}
		return toolText("Sharing failed: "+toolErrText(err, a.sealMaxBytes), nil, true), nil

	case "list_shares":
		rec := &captureWriter{header: http.Header{}}
		a.handleAPIListShares(rec, r)
		var out struct {
			Shares []apiShareRow `json:"shares"`
		}
		if rec.status != http.StatusOK || json.Unmarshal(rec.body.Bytes(), &out) != nil {
			return toolText("Listing failed.", nil, true), nil
		}
		var b strings.Builder
		if len(out.Shares) == 0 {
			b.WriteString("No shares made through the API yet.")
		}
		for _, s := range out.Shares {
			state := "active"
			if !s.Active {
				state = "expired or revoked"
			}
			exp := "never expires"
			if s.ExpiresAt != nil {
				exp = "expires " + s.ExpiresAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(&b, "- %s: %d file(s), %s, %s, %s\n", s.ID, s.Files, humanSize(s.Bytes), exp, state)
		}
		return toolText(b.String(), out, false), nil

	case "delete_share":
		var p struct {
			ID string `json:"id"`
		}
		if err := decodeArgs(args, &p); err != nil || p.ID == "" {
			return nil, &mcpError{Code: rpcInvalidParams, Message: "id is required"}
		}
		if err := a.revokeShare(r.Context(), user, p.ID); err != nil {
			return toolText("Revoking failed: "+toolErrText(err, a.sealMaxBytes), nil, true), nil
		}
		return toolText("Share "+p.ID+" revoked; its files are deleted.", map[string]string{"id": p.ID, "status": "revoked"}, false), nil
	}
	return nil, &mcpError{Code: rpcInvalidParams, Message: "unknown tool: " + name}
}

func decodeArgs(args json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.UseNumber()
	return dec.Decode(v)
}

// toolErrText says what went wrong without leaking internals: an unexpected
// failure is logged and reported generically.
func toolErrText(err error, limit int64) string {
	var se *apiStatusError
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &se):
		return se.msg
	case errors.As(err, &tooBig):
		return fmt.Sprintf("a share made through MCP holds at most %s", humanSize(limit))
	case errors.Is(err, errQuotaExceeded):
		return err.Error()
	}
	httpError(discardWriter{}, err, http.StatusInternalServerError)
	return "internal error"
}

func describeShare(res *sharedResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Shared %d file(s):\n", len(res.Files))
	for _, f := range res.Files {
		fmt.Fprintf(&b, "- %s (%s)\n", f.Name, humanSize(f.Size))
	}
	fmt.Fprintf(&b, "\nLink: %s\n\n", res.URL)
	if res.ExpiresAt != nil {
		fmt.Fprintf(&b, "Expires %s.", res.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	} else {
		b.WriteString("Never expires.")
	}
	if res.MaxDownloads != nil {
		fmt.Fprintf(&b, " Retired after %d download(s).", *res.MaxDownloads)
	}
	b.WriteString("\nGive the user the link exactly as above, including everything after #: " +
		"that part is the decryption key and Pyxis keeps no copy. The share was encrypted by " +
		"the Pyxis server, not end-to-end; the download page says so.")
	return b.String()
}

// captureWriter records a handler's response so a tool can reuse it.
type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (c *captureWriter) Header() http.Header { return c.header }
func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(b)
}
func (c *captureWriter) WriteHeader(s int) { c.status = s }

type discardWriter struct{}

func (discardWriter) Header() http.Header         { return http.Header{} }
func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (discardWriter) WriteHeader(int)             {}
