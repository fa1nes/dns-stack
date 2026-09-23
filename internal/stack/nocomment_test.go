package stack

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("定位不到仓库根目录: %v", err)
	}
	return root
}

func TestGoTreeCarriesNoComments(t *testing.T) {
	root := repoRoot(t)
	scanned := 0
	for _, top := range []string{"cmd", "internal"} {
		dir := filepath.Join(root, top)
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			scanned++
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				t.Errorf("%s 解析失败: %v", path, err)
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			for _, group := range file.Comments {
				for _, comment := range group.List {
					if strings.HasPrefix(comment.Text, "//go:") {
						continue
					}
					t.Errorf("%s:%d 有注释 %q——本项目要求全库零注释，"+
						"只有 //go: 指令是例外；解释要写进命名、失败信息或提交说明里",
						rel, fset.Position(comment.Pos()).Line, firstLine(comment.Text))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("遍历 %s 失败: %v", top, err)
		}
	}
	if scanned == 0 {
		t.Fatal("一个 .go 文件都没扫到，这条判据本身失效了")
	}
}

func firstLine(text string) string {
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		text = text[:index] + " …"
	}
	if len([]rune(text)) > 60 {
		text = string([]rune(text)[:60]) + " …"
	}
	return text
}

func heredocTag(line string) string {
	index := strings.Index(line, "<<")
	if index < 0 {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line[index+2:], "-"))
	if rest == "" || strings.HasPrefix(rest, "<") {
		return ""
	}
	rest = strings.Fields(rest)[0]
	return strings.Trim(rest, "'\"")
}

func TestInstallScriptsCarryNoComments(t *testing.T) {
	root := repoRoot(t)
	checked := 0
	for _, name := range []string{"install.sh", "install-hk.sh"} {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Skipf("读不到 %s: %v", name, err)
		}
		checked++
		closing := ""
		for number, line := range strings.Split(string(body), "\n") {
			if closing != "" {
				if strings.TrimSpace(line) == closing {
					closing = ""
				}
				continue
			}
			if tag := heredocTag(line); tag != "" {
				closing = tag
				continue
			}
			trimmed := strings.TrimSpace(line)
			if number == 0 && strings.HasPrefix(trimmed, "#!") {
				continue
			}
			if strings.HasPrefix(trimmed, "#") {
				t.Errorf("%s:%d 有注释 %q——本项目要求全库零注释，"+
					"shebang、heredoc 与字符串里的 # 才是例外", name, number+1, firstLine(trimmed))
			}
		}
	}
	if checked == 0 {
		t.Fatal("一个安装脚本都没检查到，这条判据本身失效了")
	}
}
