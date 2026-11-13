package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// `pyxis share FILE…` — the end-to-end way for a program to share files.
//
// It does on this machine what the browser does in a tab: draws the secret,
// encrypts every file chunk by chunk (seal.go), uploads only ciphertext
// through /api/v1, seals the roster, and prints the link. The server sees what
// it sees from a browser upload and nothing more, so the share carries the
// ordinary end-to-end badge. Files are streamed, so they are bounded by the
// account's upload limit, not by the server-sealing limit.

const shareUsage = `usage: pyxis share [flags] FILE...

Encrypts the files locally and shares them under one Pyxis link, which is
printed on stdout. The part after # is the key; nobody else has a copy.

Environment:
  PYXIS_URL     the instance, e.g. https://pyxis.example.org
  PYXIS_TOKEN   an API token (Account → API tokens)

Flags:
`

func runShareCLI(args []string) int {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, shareUsage)
		fs.PrintDefaults()
	}
	base := fs.String("url", os.Getenv("PYXIS_URL"), "instance URL (default $PYXIS_URL)")
	token := fs.String("token", os.Getenv("PYXIS_TOKEN"), "API token (default $PYXIS_TOKEN)")
	expires := fs.Duration("expires", 24*time.Hour, "lifetime of the link, in whole hours; 0 = never")
	maxDL := fs.Int("max-downloads", 0, "retire the link after this many file downloads (0 = no limit)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 || *base == "" || *token == "" {
		fs.Usage()
		return 2
	}
	c := &shareClient{base: strings.TrimRight(*base, "/"), token: *token, http: &http.Client{}}
	res, err := c.share(fs.Args(), *expires, *maxDL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pyxis share:", err)
		return 1
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(res)
	} else {
		fmt.Println(res.URL)
	}
	return 0
}

type shareClient struct {
	base, token string
	http        *http.Client
}

func (c *shareClient) do(req *http.Request, out any) error {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s: %s", resp.Status, e.Error)
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

func (c *shareClient) postForm(path string, form url.Values, out any) error {
	req, err := http.NewRequest(http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req, out)
}

func (c *shareClient) share(paths []string, expires time.Duration, maxDL int) (*sharedResult, error) {
	type local struct {
		path, name, typ string
		size            int64
	}
	var files []local
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", p)
		}
		name := filepath.Base(p)
		typ := mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
		if typ == "" {
			typ = "application/octet-stream"
		}
		files = append(files, local{p, name, typ, st.Size()})
	}

	form := url.Values{}
	form.Set("expires_hours", strconv.Itoa(int(expires/time.Hour)))
	form.Set("max_downloads", strconv.Itoa(maxDL))
	var batch struct {
		ID        string     `json:"id"`
		URL       string     `json:"url"`
		ExpiresAt *time.Time `json:"expiresAt"`
	}
	if err := c.postForm("/api/v1/batches", form, &batch); err != nil {
		return nil, fmt.Errorf("open share: %w", err)
	}
	keys, err := newShareKeys()
	if err != nil {
		return nil, err
	}
	defer keys.forget()

	res := &sharedResult{ID: batch.ID, ExpiresAt: batch.ExpiresAt}
	if maxDL > 0 {
		res.MaxDownloads = &maxDL
	}
	var roster []rosterEntry
	for _, f := range files {
		m, err := keys.prepareMember(batch.ID, f.name, f.typ, f.size)
		if err != nil {
			return nil, err
		}
		rowID, err := c.upload(batch.ID, f.path, m)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
		// Re-sealed after every member, as the browser does, so the link is
		// complete at every moment.
		roster = append(roster, m.entry(rowID))
		sealed, err := keys.sealRoster(batch.ID, int64(len(roster)), roster)
		if err != nil {
			return nil, err
		}
		rf := url.Values{}
		rf.Set("roster", base64.RawURLEncoding.EncodeToString(sealed))
		rf.Set("seq", strconv.Itoa(len(roster)))
		if err := c.postForm("/api/v1/batches/"+batch.ID+"/roster", rf, nil); err != nil {
			return nil, fmt.Errorf("store roster: %w", err)
		}
		res.Files = append(res.Files, sharedFile{ID: rowID, Name: f.name, Size: f.size, Type: f.typ})
	}
	link := batch.URL
	if !strings.HasPrefix(link, "http") {
		link = c.base + link
	}
	res.URL = link + "#" + keys.fragment()
	return res, nil
}

// upload streams one member as the browser's multipart form, encrypting while
// it sends; the plaintext is never buffered whole.
func (c *shareClient) upload(batchID, path string, m *sealedMember) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		b := base64.RawURLEncoding.EncodeToString
		fields := [][2]string{
			{"batch_id", batchID}, {"e2e", "1"}, {"e2e_version", strconv.Itoa(e2eVersionV5)},
			{"wrapped_key", b(m.WrappedKey)}, {"manifest", b(m.Manifest)},
			{"enc_name", b(m.EncName)}, {"plain_size", strconv.FormatInt(m.PlainSize, 10)},
		}
		for _, f := range fields {
			if err := mw.WriteField(f[0], f[1]); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		// Named after nothing: a multipart filename is plaintext metadata.
		part, err := mw.CreateFormFile("file", "blob.enc")
		if err == nil {
			err = m.encryptTo(part, src)
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
	}()

	req, err := http.NewRequest(http.MethodPost, c.base+"/api/v1/upload", pr)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(req, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("the server returned no file id")
	}
	return out.ID, nil
}
