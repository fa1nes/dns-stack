package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dns-stack/dns-stack/internal/helper"
	"github.com/dns-stack/dns-stack/internal/panel"
)

func cmdPanelAuth(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: dns-stack panel-auth <set-password|disable-totp> [参数]")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("panel-auth "+sub, flag.ContinueOnError)
	authPath := fs.String("auth", envOr("DNS_STACK_AUTH", panel.DefaultAuthPath), "面板认证文件路径")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	switch sub {
	case "set-password":
		password := os.Getenv("PW")
		if password == "" {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			password = strings.TrimRight(string(raw), "\r\n")
		}
		if password == "" {
			return fmt.Errorf("未提供密码：用 PW 环境变量传入，或从 stdin 读入")
		}
		if err := helper.SetPanelPassword(*authPath, password); err != nil {
			return err
		}
		fmt.Println("面板密码已更新（存的是 scrypt 哈希；会话密钥同时轮换，旧会话立即失效）")
		return nil

	case "disable-totp":
		changed, err := helper.DisableTOTP(*authPath)
		if err != nil {
			return err
		}
		if changed {
			fmt.Println("二次认证已关闭，现在仅凭密码即可登录")
			return nil
		}
		fmt.Println("二次认证本就未启用，未做改动")
		return nil
	}
	return fmt.Errorf("未知子命令: panel-auth %s", sub)
}
