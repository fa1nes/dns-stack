package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const mockTag = `<script src="mock-api.js"></script>` + "\n"

func main() {
	addr := flag.String("addr", "127.0.0.1:8791", "监听地址")
	root := flag.String("root", ".", "web 目录")
	flag.Parse()

	base, err := filepath.Abs(*root)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "index.html")); err != nil {
		log.Fatalf("%s 下没有 index.html，用 --root 指向仓库的 web/ 目录", base)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if strings.Contains(name, "..") {
			http.Error(w, "非法路径", http.StatusBadRequest)
			return
		}
		path := filepath.Join(base, filepath.FromSlash(name))
		data, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasSuffix(name, ".html") {
			data = bytes.Replace(data, []byte("</head>"), []byte(mockTag+"</head>"), 1)
		}
		w.Header().Set("Content-Type", contentType(name))
		w.Write(data)
	})

	fmt.Printf("前端开发服务器: http://%s/  (已注入 mock-api.js，不需要任何后端)\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func contentType(name string) string {
	switch filepath.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".json":
		return "application/json; charset=utf-8"
	}
	return "application/octet-stream"
}
