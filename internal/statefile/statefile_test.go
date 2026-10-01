package statefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinesSkipsBlanksAndCommentsAndKeepsLongLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	long := strings.Repeat("x", 200*1024)
	if err := os.WriteFile(path, []byte("# header\n\n  1.2.3.0/24  \n\t# indented comment\n"+long+"\r\nlast"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := Lines(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[0] != "1.2.3.0/24" || lines[1] != long || lines[2] != "last" {
		t.Fatalf("得到 %d 行，首行 %q——超过 64KB 的行此前会让 bufio.Scanner 静默停下，"+
			"后面的行全部丢失，而调用方从不检查 Scanner.Err()", len(lines), lines[0])
	}
}

func TestLinesReportsAMissingFileInsteadOfAnEmptyList(t *testing.T) {
	_, err := Lines(filepath.Join(t.TempDir(), "absent.txt"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v——调用方要能分清「文件不存在」和「文件是空的」，selfcheck 靠这个区别报 -1", err)
	}
}
