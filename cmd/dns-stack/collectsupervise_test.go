package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestAFailedCollectorNeverStopsMosproxyFromLogging(t *testing.T) {
	reader, writer := io.Pipe()
	var warn bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- consumeWithoutBlocking(reader, func(io.Reader) error { return errors.New("数据库打不开") }, &warn)
	}()

	written := make(chan error, 1)
	go func() {
		_, err := writer.Write(bytes.Repeat([]byte("mosproxy log line\n"), 64*1024))
		writer.Close()
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collector 失败后没人读管道，mosproxy 写日志被卡住——" +
			"管道缓冲写满后它的查询处理也会跟着阻塞，统计这个旁路就把 DNS 拖停了")
	}
	if err := <-done; err == nil || !strings.Contains(warn.String(), "DNS 照常服务") {
		t.Fatalf("collector 失败必须报出来，err=%v warn=%q", err, warn.String())
	}
}
