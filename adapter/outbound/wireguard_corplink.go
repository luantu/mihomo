package outbound

// corplink (锐捷 CorpLink VPN) 的认证与对端信息获取。
// 复用 corplink 客户端的 /vpn/conn API：用 TOTP + cookie 换取当前会话
// 分配的隧道 IP 与服务器公钥，使 wireguard 节点无需外部客户端即可独立建立隧道。

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/tls"

	"github.com/metacubex/mihomo/log"
)

// CorplinkOption 描述 corplink 认证所需参数。
type CorplinkOption struct {
	// APIServer 为 corplink 控制面地址（如 https://140.224.74.169:34443），
	// 用于调用 /vpn/conn 获取会话信息。为空时不做认证。
	APIServer string `proxy:"corplink-api-server,omitempty"`
	// Code 为 base32 编码的 TOTP 密钥（corplink config.json 的 code 字段）。
	Code string `proxy:"corplink-code,omitempty"`
	// CookieFile 为 corplink 保存的 cookie 文件路径（utun16_cookies.json）。
	CookieFile string `proxy:"corplink-cookie-file,omitempty"`
	// PublicKey 为本机 wireguard 公钥（base64），用于 /vpn/conn 请求。
	PublicKey string `proxy:"corplink-public-key,omitempty"`
}

type corplinkRespWgInfo struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	Data      *struct {
		IP        string `json:"ip"`
		IPv6      string `json:"ipv6"`
		IPMask    string `json:"ip_mask"`
		Mode      int    `json:"mode"`
		PublicKey string `json:"public_key"`
		Setting   *struct {
			VPNMTU int `json:"vpn_mtu"`
		} `json:"setting"`
	} `json:"data"`
}

type corplinkWgInfo struct {
	IP            string
	ServerPubKey  string
	ServerPubKeyHex string
	MTU           int
}

// fetchCorplinkWgInfo 调用 corplink /vpn/conn API 获取当前会话的 wg 信息。
func fetchCorplinkWgInfo(opt CorplinkOption) (*corplinkWgInfo, error) {
	if opt.APIServer == "" {
		return nil, errors.New("corplink api server not set")
	}

	otp, err := corplinkTotp(opt.Code)
	if err != nil {
		return nil, err
	}

	csrf, cookieStr, err := loadCorplinkCookie(opt.CookieFile)
	if err != nil {
		return nil, err
	}

	apiURL := strings.TrimSuffix(opt.APIServer, "/") + "/vpn/conn?os=Android&os_version=2"
	// corplink /vpn/conn 的 public_key 字段期望 base64 编码；
	// 兼容 hex 输入（option.PublicKey 在 NewWireGuard 中已被统一为 hex）。
	reqPubKey := opt.PublicKey
	if b, err := hex.DecodeString(reqPubKey); err == nil && len(b) == 32 {
		reqPubKey = base64.StdEncoding.EncodeToString(b)
	}
	body, _ := json.Marshal(map[string]string{
		"public_key": reqPubKey,
		"otp":        otp,
	})
	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.14.9")
	if cookieStr != "" {
		req.Header.Set("Cookie", cookieStr)
	}
	if csrf != "" {
		req.Header.Set("csrf-token", csrf)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	// corplink 控制面使用自签/无 IP SAN 证书，跳过校验（与 corplink 客户端行为一致）。
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("corplink api status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var wg corplinkRespWgInfo
	if err := json.Unmarshal(raw, &wg); err != nil {
		return nil, fmt.Errorf("corplink api parse error: %v", err)
	}
	if wg.Code != 0 || wg.Data == nil {
		return nil, fmt.Errorf("corplink api code %d: %s", wg.Code, wg.Message)
	}

	serverPubB64 := wg.Data.PublicKey
	serverPubHex := ""
	if b, err := base64.StdEncoding.DecodeString(serverPubB64); err == nil {
		serverPubHex = hex.EncodeToString(b)
	}
	info := &corplinkWgInfo{
		IP:              wg.Data.IP,
		ServerPubKey:    serverPubB64,
		ServerPubKeyHex: serverPubHex,
		MTU:             0,
	}
	if wg.Data.Setting != nil {
		info.MTU = wg.Data.Setting.VPNMTU
	}
	log.Infoln("[WG-Corplink] fetched wg_info: ip=%s server_pubkey=%s", info.IP, serverPubB64)
	return info, nil
}

// corplinkTotp 基于 base32 密钥生成当前 30 秒槽的 6 位 TOTP。
func corplinkTotp(codeB32 string) (string, error) {
	if codeB32 == "" {
		return "", errors.New("corplink code not set")
	}
	padding := strings.Repeat("=", (8-len(codeB32)%8)%8)
	key, err := base32.StdEncoding.DecodeString(codeB32 + padding)
	if err != nil {
		return "", fmt.Errorf("corplink code decode: %v", err)
	}
	counter := uint64(time.Now().Unix() / 30)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	val := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", val%1000000), nil
}

// loadCorplinkCookie 从 corplink 的 cookie 文件中读取 csrf-token 与 session。
func loadCorplinkCookie(path string) (csrf, cookieStr string, err error) {
	if path == "" {
		return "", "", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("corplink cookie file: %v", err)
	}
	defer f.Close()

	var cookies []struct {
		RawCookie string `json:"raw_cookie"`
	}
	if err := json.NewDecoder(f).Decode(&cookies); err != nil {
		return "", "", fmt.Errorf("corplink cookie parse: %v", err)
	}
	var parts []string
	for _, c := range cookies {
		raw := c.RawCookie
		seg := strings.SplitN(raw, ";", 2)[0]
		parts = append(parts, seg)
		name := strings.SplitN(seg, "=", 2)[0]
		if name == "csrf-token" {
			csrf = strings.SplitN(seg, "=", 2)[1]
		}
	}
	return csrf, strings.Join(parts, "; "), nil
}
