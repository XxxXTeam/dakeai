package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	tempemail "github.com/XxxXTeam/tempmail-sdk/sdk/go"
)

/*
 * ANSI 颜色常量
 * @功能 终端彩色输出
 */
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorPurple = "\033[35m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
)

/*
 * 业务常量
 * @功能 API 地址、轮询配置、默认参数
 */
const (
	baseURL            = "https://codex.dakeai.cc"
	sendVerifyCodePath = "/api/v1/auth/send-verify-code"
	registerPath       = "/api/v1/auth/register"
	createKeyPath      = "/api/v1/keys"
	apiKeyFile         = "api_keys.txt"
	pollInterval       = 5 * time.Second
	pollTimeout        = 120 * time.Second
	defaultKeyName     = "auto-generated"
	defaultGroupID     = 5
)

/*
 * 全局统计与同步
 * @successCount 成功计数
 * @failCount    失败计数
 * @keyMutex     文件写入互斥锁
 */
var (
	successCount int64
	failCount    int64
	keyMutex     sync.Mutex
	debugMode    bool
)

var commonHeaders = map[string]string{
	"accept":             "application/json, text/plain, */*",
	"accept-language":    "zh",
	"cache-control":      "no-cache",
	"content-type":       "application/json",
	"dnt":                "1",
	"origin":             baseURL,
	"pragma":             "no-cache",
	"priority":           "u=1, i",
	"sec-ch-ua":          `"Not:A-Brand";v="99", "Microsoft Edge";v="145", "Chromium";v="145"`,
	"sec-ch-ua-mobile":   "?0",
	"sec-ch-ua-platform": `"Windows"`,
	"sec-fetch-dest":     "empty",
	"sec-fetch-mode":     "cors",
	"sec-fetch-site":     "same-origin",
	"user-agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0",
}

type SendVerifyCodeReq struct {
	Email string `json:"email"`
}

type RegisterReq struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	VerifyCode string `json:"verify_code"`
}

type CreateKeyReq struct {
	Name    string `json:"name"`
	GroupID int    `json:"group_id"`
}

type APIResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type RegisterData struct {
	AccessToken string `json:"access_token"`
}

type KeyData struct {
	ID      int    `json:"id"`
	UserID  int    `json:"user_id"`
	Key     string `json:"key"`
	Name    string `json:"name"`
	GroupID int    `json:"group_id"`
	Status  string `json:"status"`
}

/*
 * doRequest 发送 HTTP 请求
 * @功能 封装请求发送，自动设置公共请求头
 */
func doRequest(method, url string, body interface{}, token string, referer string) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("序列化请求体失败: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	for k, v := range commonHeaders {
		req.Header.Set(k, v)
	}
	if referer != "" {
		req.Header.Set("referer", referer)
	}
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	return respBody, nil
}

/*
 * parseResponse 解析 API 响应
 * @功能 解析 JSON 并检查返回码
 */
func parseResponse(data []byte) (*APIResponse, error) {
	var resp APIResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if resp.Code != 0 {
		return &resp, fmt.Errorf("API 错误: code=%d, msg=%s", resp.Code, resp.Message)
	}
	return &resp, nil
}

/*
 * generatePassword 生成随机密码
 * @功能 生成指定长度的随机密码
 */
func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-"
	password := make([]byte, length)
	for i := range password {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		password[i] = charset[n.Int64()]
	}
	return string(password)
}

/*
 * extractVerifyCode 从邮件中提取验证码
 * @功能 多模式正则匹配 4-8 位数字验证码
 */
func extractVerifyCode(text, html string) (string, bool) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:verification|verify|code|验证码|驗證碼)[:\s]*?(\d{4,8})`),
		regexp.MustCompile(`(?i)(\d{4,8})[\s]*?(?:is your|为您的|是您的)`),
		regexp.MustCompile(`\b(\d{6})\b`),
		regexp.MustCompile(`\b(\d{4})\b`),
	}
	htmlTagRe := regexp.MustCompile(`<[^>]*>`)
	for _, content := range []string{text, html} {
		if content == "" {
			continue
		}
		clean := htmlTagRe.ReplaceAllString(content, " ")
		for _, re := range patterns {
			matches := re.FindStringSubmatch(clean)
			if len(matches) > 1 {
				return matches[1], true
			}
		}
	}
	return "", false
}

/*
 * saveAPIKey 线程安全地保存 API Key 到文件
 * @功能 追加写入 api_keys.txt
 */
func saveAPIKey(apiKey string, email string) error {
	keyMutex.Lock()
	defer keyMutex.Unlock()

	f, err := os.OpenFile(apiKeyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s | %s | %s\n", time.Now().Format("2006-01-02 15:04:05"), email, apiKey)
	return err
}

/*
 * logColor 彩色日志输出
 * @功能 带颜色前缀的格式化输出
 */
func logColor(color, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s%s %s\n", color, time.Now().Format("15:04:05"), colorReset, msg)
}

/*
 * debugLog debug 模式日志
 * @功能 仅在 debug 模式下输出详细信息
 */
func debugLog(workerID int, format string, args ...interface{}) {
	if !debugMode {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s%s %s[W%d]%s %s%s%s\n",
		colorDim, time.Now().Format("15:04:05"), colorReset,
		colorPurple, workerID, colorReset,
		colorDim, msg, colorReset)
}

/*
 * runRound 执行一轮完整的注册流程
 * @功能 生成临时邮箱 → 发送验证码 → 轮询邮件 → 注册 → 创建 API Key
 * @param workerID 工作线程编号
 * @return apiKey 和 error
 */
func runRound(workerID int) (string, error) {
	/* 步骤1: 生成临时邮箱（随机渠道） */
	debugLog(workerID, "[1/5] 生成临时邮箱...")
	mailClient := tempemail.NewClient()
	emailInfo, err := mailClient.Generate(nil)
	if err != nil {
		return "", fmt.Errorf("邮箱生成失败: %w", err)
	}
	email := emailInfo.Email
	debugLog(workerID, "[1/5] 邮箱: %s (渠道: %s)", email, emailInfo.Channel)

	/* 步骤2: 发送验证码 */
	debugLog(workerID, "[2/5] 发送验证码到 %s", email)
	respData, err := doRequest("POST", baseURL+sendVerifyCodePath, SendVerifyCodeReq{Email: email}, "", baseURL+"/email-verify")
	if err != nil {
		return "", fmt.Errorf("发送验证码失败: %w", err)
	}
	if _, err := parseResponse(respData); err != nil {
		debugLog(workerID, "[2/5] 发送验证码响应: %s", string(respData))
		return "", fmt.Errorf("发送验证码失败: %w", err)
	}
	debugLog(workerID, "[2/5] 验证码已发送")

	/* 步骤3: 轮询获取验证码 */
	debugLog(workerID, "[3/5] 开始轮询邮件...")
	var verifyCode string
	deadline := time.Now().Add(pollTimeout)
	pollCount := 0
	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		pollCount++
		result, err := mailClient.GetEmails(nil)
		if err != nil {
			debugLog(workerID, "[3/5] 第%d次轮询失败: %v", pollCount, err)
			continue
		}
		debugLog(workerID, "[3/5] 第%d次轮询, 收到 %d 封邮件", pollCount, len(result.Emails))
		for _, mail := range result.Emails {
			debugLog(workerID, "[3/5] 邮件 - 发件人: %s, 主题: %s", mail.From, mail.Subject)
			if code, ok := extractVerifyCode(mail.Text, mail.HTML); ok {
				verifyCode = code
				break
			}
		}
		if verifyCode != "" {
			break
		}
	}
	if verifyCode == "" {
		return "", fmt.Errorf("验证码超时(轮询%d次)", pollCount)
	}
	debugLog(workerID, "[3/5] 提取到验证码: %s", verifyCode)

	/* 步骤4: 注册 */
	debugLog(workerID, "[4/5] 注册中...")
	password := generatePassword(16)
	registerBody := RegisterReq{Email: email, Password: password, VerifyCode: verifyCode}
	respData, err = doRequest("POST", baseURL+registerPath, registerBody, "", baseURL+"/email-verify")
	if err != nil {
		return "", fmt.Errorf("注册失败: %w", err)
	}
	apiResp, err := parseResponse(respData)
	if err != nil {
		debugLog(workerID, "[4/5] 注册响应: %s", string(respData))
		return "", fmt.Errorf("注册失败: %w", err)
	}
	var regData RegisterData
	if err := json.Unmarshal(apiResp.Data, &regData); err != nil {
		debugLog(workerID, "[4/5] 注册data: %s", string(apiResp.Data))
		return "", fmt.Errorf("解析注册数据失败: %w", err)
	}
	if regData.AccessToken == "" {
		debugLog(workerID, "[4/5] 注册data: %s", string(apiResp.Data))
		return "", fmt.Errorf("未返回 Token")
	}
	debugLog(workerID, "[4/5] 注册成功, Token: %s...%s", regData.AccessToken[:20], regData.AccessToken[len(regData.AccessToken)-10:])

	/* 步骤5: 创建 API Key */
	debugLog(workerID, "[5/5] 创建 API Key...")
	createKeyBody := CreateKeyReq{Name: defaultKeyName, GroupID: defaultGroupID}
	respData, err = doRequest("POST", baseURL+createKeyPath, createKeyBody, regData.AccessToken, baseURL+"/keys")
	if err != nil {
		return "", fmt.Errorf("创建Key失败: %w", err)
	}
	apiResp, err = parseResponse(respData)
	if err != nil {
		debugLog(workerID, "[5/5] 创建Key响应: %s", string(respData))
		return "", fmt.Errorf("创建Key失败: %w", err)
	}
	var keyData KeyData
	if err := json.Unmarshal(apiResp.Data, &keyData); err != nil {
		return "", fmt.Errorf("解析Key数据失败: %w", err)
	}
	debugLog(workerID, "[5/5] Key创建成功: %s", keyData.Key)

	/* 保存到文件 */
	saveAPIKey(keyData.Key, email)

	return keyData.Key, nil
}

/*
 * worker 工作线程
 * @功能 循环执行注册流程直到目标达成或被取消
 * @param workerID 线程编号
 * @param remaining 剩余目标数量（原子操作）
 * @param wg 等待组
 */
func worker(workerID int, remaining *int64, wg *sync.WaitGroup) {
	defer wg.Done()

	for atomic.LoadInt64(remaining) > 0 {
		apiKey, err := runRound(workerID)
		if err != nil {
			atomic.AddInt64(&failCount, 1)
			logColor(colorRed, "%s[W%d]%s %s✗%s %s",
				colorPurple, workerID, colorReset,
				colorRed, colorReset,
				err.Error())
			continue
		}

		sc := atomic.AddInt64(&successCount, 1)
		left := atomic.AddInt64(remaining, -1)
		logColor(colorGreen, "%s[W%d]%s %s✓%s %s%s%s  %s(%d/%d)%s",
			colorPurple, workerID, colorReset,
			colorBold+colorGreen, colorReset,
			colorCyan, apiKey, colorReset,
			colorDim, sc, sc+left, colorReset)

		if left <= 0 {
			return
		}
	}
}

/*
 * printBanner 打印启动横幅
 * @功能 显示工具名称和运行参数
 */
func printBanner(threads, count int) {
	fmt.Printf("  %s线程: %s%d%s  目标: %s%d%s  保存: %s%s%s\n\n",
		colorDim, colorYellow, threads, colorDim,
		colorYellow, count, colorDim,
		colorYellow, apiKeyFile, colorReset)
}

/*
 * printSummary 打印运行总结
 * @功能 显示成功数、失败数和耗时
 */

func main() {
	/*
	 * 命令行参数
	 * @param threads 并发线程数
	 * @param count   目标获取数量
	 */
	threads := flag.Int("threads", 1, "并发线程数")
	count := flag.Int("count", 1, "目标获取 Key 数量")
	debug := flag.Bool("debug", false, "调试模式，输出每步详细信息")
	flag.Parse()
	debugMode = *debug
	printBanner(*threads, *count)
	remaining := int64(*count)

	var wg sync.WaitGroup
	for i := 1; i <= *threads; i++ {
		wg.Add(1)
		go worker(i, &remaining, &wg)
	}
	wg.Wait()

}
