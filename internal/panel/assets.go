package panel

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"path"
	"strings"
	"sync"

	webfs "github.com/dns-stack/dns-stack/web"
)

type staticAsset struct {
	body        []byte
	compressed  []byte
	etag        string
	contentType string
}

var assets = sync.OnceValue(loadAssets)

func loadAssets() map[string]*staticAsset {
	out := map[string]*staticAsset{}
	_ = fs.WalkDir(webfs.Files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(webfs.Files, name)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(data)
		item := &staticAsset{
			body:        data,
			etag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
			contentType: contentTypeOf(name),
		}
		if len(data) >= gzipMinSize {
			var buf bytes.Buffer
			if zw, zerr := gzip.NewWriterLevel(&buf, gzip.BestCompression); zerr == nil {
				if _, werr := zw.Write(data); werr == nil && zw.Close() == nil &&
					buf.Len() < len(data) {
					item.compressed = buf.Bytes()
				}
			}
		}
		out[name] = item
		return nil
	})
	return out
}

func contentTypeOf(name string) string {
	if value := mime.TypeByExtension(path.Ext(name)); value != "" {
		return value
	}
	switch path.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	}
	return "application/octet-stream"
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag ||
			strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}
