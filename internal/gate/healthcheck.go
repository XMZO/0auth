package gate

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func RunHealthcheck(cfg Config) error {
	resp, err := http.Get(healthcheckURL(cfg.ListenAddr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		return fmt.Errorf("unexpected healthcheck response: %d %q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func runHealthcheck(cfg Config) error {
	return RunHealthcheck(cfg)
}

func healthcheckURL(listenAddr string) string {
	address := strings.TrimSpace(listenAddr)
	if address == "" {
		address = defaultListenAddr
	}
	if strings.HasPrefix(address, ":") {
		address = "127.0.0.1" + address
	}
	return "http://" + address + healthPath
}
