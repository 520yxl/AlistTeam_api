package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config 保存授权所需的参数和授权范围
type Config struct {
	Alipan struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		DriveID      string   `json:"drive_id"`
		Scope        []string `json:"scope"`
	} `json:"alipan"`
	
	OneDrive struct {
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scope        []string `json:"scope"`
	} `json:"onedrive"`
	
	Server struct {
		Port int `json:"port"`
	} `json:"server"`
}

// 全局配置变量
var config Config

// 从文件加载配置
func loadConfig(configPath string) error {
	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 创建默认配置文件
		defaultConfig := Config{
			Alipan: struct {
				ClientID     string   `json:"client_id"`
				ClientSecret string   `json:"client_secret"`
				DriveID      string   `json:"drive_id"`
				Scope        []string `json:"scope"`
			}{
				ClientID:     "",
				ClientSecret: "",
				DriveID:      "",
				Scope: []string{
					"user:base",
					"file:all:read",
					"file:all:write",
					"album:shared:read",
					"file:share:write",
				},
			},
			OneDrive: struct {
				ClientID     string   `json:"client_id"`
				ClientSecret string   `json:"client_secret"`
				Scope        []string `json:"scope"`
			}{
				ClientID:     "",
				ClientSecret: "",
				Scope: []string{
					"Files.ReadWrite.All",
					"offline_access",
				},
			},
			Server: struct {
				Port int `json:"port"`
			}{
				Port: 5280,
			},
		}
		
		// 序列化配置
		data, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("创建默认配置失败: %v", err)
		}
		
		// 写入配置文件
		err = ioutil.WriteFile(configPath, data, 0644)
		if err != nil {
			return fmt.Errorf("写入配置文件失败: %v", err)
		}
		
		log.Printf("已创建默认配置文件: %s\n", configPath)
		log.Println("请编辑配置文件并重新启动程序")
		os.Exit(0)
	}
	
	// 读取配置文件
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}
	
	// 解析配置
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}
	
	log.Printf("已加载配置文件: %s\n", configPath)
	return nil
}

// 处理跨域请求
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
}

// 从map中安全获取字符串值
func getStringFromMap(m map[string]interface{}, key string, defaultValue string) string {
	value, exists := m[key]
	if !exists {
		return defaultValue
	}
	strValue, ok := value.(string)
	if !ok {
		return defaultValue
	}
	return strValue
}

// 发送 POST 请求
func postRequest(urlStr string, data url.Values) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.PostForm(urlStr, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// 动态检测请求协议
func detectProtocol(r *http.Request) string {
	// 详细日志记录开始
	log.Println("===== 开始检测请求协议 =====")
	
	// 1. 检查直接TLS连接
	if r.TLS != nil {
		log.Println("✓ 通过直接TLS连接检测到HTTPS")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ 未检测到直接TLS连接")
	
	// 2. 检查常见的代理头
	headersToCheck := []string{
		"X-Forwarded-Proto",
		"X-Forwarded-SSL",
		"CF-Visitor",
		"X-ARR-SSL",
		"X-Cloud-Trace-Context",
		"Front-End-Https",
		"X-Url-Scheme",
		"X-Forwarded-Protocol",
		"X-Forwarded-Host",
		"X-ProxyUser-Ip",
	}
	
	// 检查每个可能的代理头
	for _, header := range headersToCheck {
		value := r.Header.Get(header)
		log.Printf("检查头 '%s': %s", header, value)
		
		if value != "" {
			switch header {
			case "X-Forwarded-Proto":
				if strings.ToLower(value) == "https" {
					log.Println("✓ 通过X-Forwarded-Proto检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "X-Forwarded-SSL":
				if strings.ToLower(value) == "on" {
					log.Println("✓ 通过X-Forwarded-SSL检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "CF-Visitor":
				if strings.Contains(value, "\"scheme\":\"https\"") {
					log.Println("✓ 通过CF-Visitor检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "X-ARR-SSL":
				if value != "" {
					log.Println("✓ 通过X-ARR-SSL检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "X-Cloud-Trace-Context":
				if value != "" {
					log.Println("✓ 通过X-Cloud-Trace-Context检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "Front-End-Https":
				if strings.ToLower(value) == "on" {
					log.Println("✓ 通过Front-End-Https检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "X-Url-Scheme":
				if strings.ToLower(value) == "https" {
					log.Println("✓ 通过X-Url-Scheme检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "X-Forwarded-Protocol":
				if strings.ToLower(value) == "https" {
					log.Println("✓ 通过X-Forwarded-Protocol检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "X-Forwarded-Host":
				if strings.Contains(value, ":443") {
					log.Println("✓ 通过X-Forwarded-Host中的端口检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			case "X-ProxyUser-Ip":
				if value != "" {
					log.Println("✓ 通过X-ProxyUser-Ip检测到HTTPS")
					log.Println("===== 协议检测完成 =====")
					return "https"
				}
			}
		}
	}
	
	// 3. 检查Host头中的端口
	host := r.Host
	if strings.Contains(host, ":443") {
		log.Println("✓ 通过Host头中的端口检测到HTTPS")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ Host头中未检测到HTTPS端口")
	
	// 4. 检查请求URI
	if strings.HasPrefix(r.RequestURI, "https://") {
		log.Println("✓ 通过请求URI检测到HTTPS")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ 请求URI中未检测到HTTPS")
	
	// 5. 检查请求的Referer头
	referer := r.Header.Get("Referer")
	if strings.HasPrefix(referer, "https://") {
		log.Println("✓ 通过Referer头检测到HTTPS")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ Referer头中未检测到HTTPS")
	
	// 6. 检查是否是宝塔面板环境
	if r.Header.Get("X-Bt-Proxy") != "" {
		log.Println("✓ 通过宝塔面板代理头检测到HTTPS")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ 未检测到宝塔面板代理头")
	
	// 7. 检查请求的User-Agent
	userAgent := r.Header.Get("User-Agent")
	if strings.Contains(strings.ToLower(userAgent), "cloudflare") {
		log.Println("✓ 通过User-Agent检测到Cloudflare代理")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ User-Agent中未检测到Cloudflare")
	
	// 8. 检查请求的Origin头
	origin := r.Header.Get("Origin")
	if strings.HasPrefix(origin, "https://") {
		log.Println("✓ 通过Origin头检测到HTTPS")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ Origin头中未检测到HTTPS")
	
	// 9. 检查请求的Cookie
	cookies := r.Header.Get("Cookie")
	if strings.Contains(cookies, "__cfduid=") || strings.Contains(cookies, "__cf_bm=") {
		log.Println("✓ 通过Cookie检测到Cloudflare")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ Cookie中未检测到Cloudflare")
	
	// 10. 检查是否是常见的HTTPS域名后缀
	if strings.HasSuffix(r.Host, ".com") || 
	   strings.HasSuffix(r.Host, ".net") || 
	   strings.HasSuffix(r.Host, ".org") || 
	   strings.HasSuffix(r.Host, ".io") || 
	   strings.HasSuffix(r.Host, ".cn") {
		log.Println("⚠ 检测到常见HTTPS域名后缀，假设使用HTTPS")
		log.Println("===== 协议检测完成 =====")
		return "https"
	}
	log.Println("✗ 未检测到常见HTTPS域名后缀")
	
	// 11. 最后的手段：强制使用HTTPS（这是最后的防线）
	log.Println("⚠ 无法检测到协议，默认强制使用HTTPS")
	log.Println("===== 协议检测完成 =====")
	return "https"
}

// 初始化授权请求
func initAuthorizationFlow(w http.ResponseWriter, r *http.Request, clientID, clientSecret, redirectURI string, isAlipan bool) {
	if clientID == "" || clientSecret == "" {
		http.Error(w, `{"error": "缺少客户端凭证参数"}`, http.StatusBadRequest)
		return
	}

	// 生成带参数的 state
	stateData := map[string]interface{}{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"timestamp":     time.Now().Unix(),
	}
	if isAlipan {
		sign := fmt.Sprintf("%x", crc32.ChecksumIEEE([]byte(clientID+clientSecret)))
		stateData["sign"] = sign
	}
	stateJSON, _ := json.Marshal(stateData)
	state := base64.StdEncoding.EncodeToString(stateJSON)

	var authURL string
	var scope string
	
	if isAlipan {
		// 从配置中获取阿里云盘授权范围
		scope = ""
		for i, s := range config.Alipan.Scope {
			if i > 0 {
				scope += ","
			}
			scope += s
		}
		
		authURL = "https://openapi.alipan.com/oauth/authorize?" + url.Values{
			"client_id":     {clientID},
			"redirect_uri":  {redirectURI},
			"response_type": {"code"},
			"scope":         {scope},
			"state":         {state},
		}.Encode()
	} else {
		// 从配置中获取OneDrive授权范围
		scope = ""
		for i, s := range config.OneDrive.Scope {
			if i > 0 {
				scope += " "
			}
			scope += s
		}
		
		authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + url.Values{
			"client_id":     {clientID},
			"response_type": {"code"},
			"redirect_uri":  {redirectURI},
			"scope":         {scope},
			"state":         {state},
			"response_mode": {"query"},
		}.Encode()
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// 处理回调
func handleAuthorizationCallback(w http.ResponseWriter, r *http.Request, redirectURI string, isAlipan bool) {
	query := r.URL.Query()
	if query.Get("state") == "" || query.Get("code") == "" {
		http.Error(w, `{"error": "无效的授权响应"}`, http.StatusBadRequest)
		return
	}

	// 验证 state 签名
	stateJSON, err := base64.StdEncoding.DecodeString(query.Get("state"))
	if err != nil {
		http.Error(w, `{"error": "无效的 state 参数"}`, http.StatusBadRequest)
		return
	}
	var state map[string]interface{}
	err = json.Unmarshal(stateJSON, &state)
	if err != nil {
		http.Error(w, `{"error": "无效的 state 参数"}`, http.StatusBadRequest)
		return
	}

	if isAlipan {
		expectedSign := fmt.Sprintf("%x", crc32.ChecksumIEEE([]byte(getStringFromMap(state, "client_id", "")+getStringFromMap(state, "client_secret", ""))))
		if getStringFromMap(state, "sign", "") != expectedSign {
			http.Error(w, `{"error": "参数签名验证失败"}`, http.StatusForbidden)
			return
		}
	}

	// 请求访问令牌
	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {query.Get("code")},
		"client_id":     {getStringFromMap(state, "client_id", "")},
		"client_secret": {getStringFromMap(state, "client_secret", "")},
		"redirect_uri":  {redirectURI},
	}

	var tokenURL string
	if isAlipan {
		tokenURL = "https://openapi.alipan.com/oauth/access_token"
	} else {
		tokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	}

	response, err := postRequest(tokenURL, tokenData)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "令牌获取失败", "details": "%v"}`, err), http.StatusInternalServerError)
		return
	}

	if refreshToken, ok := response["refresh_token"]; ok {
		result := map[string]interface{}{
			"refresh_token": refreshToken,
			"access_token":  response["access_token"],
			"expires_in":    response["expires_in"],
		}
		if isAlipan {
			result["drive_id"] = response["drive_id"]
		}
		jsonResult, _ := json.Marshal(result)
		w.Write(jsonResult)
	} else {
		code := ""
		message := ""
		if isAlipan {
			if c, ok := response["code"]; ok {
				code = fmt.Sprintf("%v", c)
			}
			if m, ok := response["message"]; ok {
				message = fmt.Sprintf("%v", m)
			}
		} else {
			details, _ := json.Marshal(response)
			message = string(details)
		}
		http.Error(w, fmt.Sprintf(`{"error": "令牌获取失败", "code": "%s", "message": "%s"}`, code, message), http.StatusInternalServerError)
	}
}

// 处理令牌刷新
func handleTokenRefresh(w http.ResponseWriter, r *http.Request, isAlipan bool) {
	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, `{"error": "请求格式错误，请提供JSON数据"}`, http.StatusBadRequest)
		log.Printf("JSON解析错误: %v\n", err)
		return
	}

	refreshToken := getStringFromMap(data, "refresh_token", "")
	clientID := getStringFromMap(data, "client_id", "")
	clientSecret := getStringFromMap(data, "client_secret", "")

	if refreshToken == "" || clientID == "" || clientSecret == "" {
		http.Error(w, `{"error": "缺少必要参数: refresh_token, client_id, client_secret"}`, http.StatusBadRequest)
		return
	}

	tokenData := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	if isAlipan {
		driveID := getStringFromMap(data, "drive_id", "")
		if driveID != "" {
			tokenData.Set("drive_id", driveID)
		}
	}

	var tokenURL string
	if isAlipan {
		tokenURL = "https://openapi.alipan.com/oauth/access_token"
	} else {
		tokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	}

	response, err := postRequest(tokenURL, tokenData)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "令牌刷新失败", "details": "%v"}`, err), http.StatusUnauthorized)
		return
	}

	if accessToken, ok := response["access_token"]; ok {
		newRefreshToken := refreshToken
		if rt, ok := response["refresh_token"]; ok {
			newRefreshToken = rt.(string)
		}
		result := map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": newRefreshToken,
			"expires_in":    response["expires_in"],
		}
		if isAlipan {
			result["drive_id"] = response["drive_id"]
		}
		jsonResult, _ := json.Marshal(result)
		w.Write(jsonResult)
	} else {
		code := ""
		message := ""
		if isAlipan {
			if c, ok := response["code"]; ok {
				code = fmt.Sprintf("%v", c)
			}
			if m, ok := response["message"]; ok {
				message = fmt.Sprintf("%v", m)
			}
		} else {
			details, _ := json.Marshal(response)
			message = string(details)
		}
		http.Error(w, fmt.Sprintf(`{"error": "令牌刷新失败", "code": "%s", "message": "%s"}`, code, message), http.StatusUnauthorized)
	}
}

// 主处理函数
func handler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	log.Printf("请求: %s %s\n", r.Method, r.URL.Path)
	log.Printf("客户端IP: %s\n", r.RemoteAddr)
	log.Printf("请求头: %v\n", r.Header)  // 添加请求头日志，便于调试

	// 动态检测请求协议
	protocol := detectProtocol(r)
	log.Printf("检测到的协议: %s\n", protocol)
	
	// 生成重定向 URI
	redirectURI := protocol + "://" + r.Host + r.URL.Path
	log.Printf("生成的重定向 URI: %s\n", redirectURI)
	
	// 合并请求参数
	requestParams := make(map[string]interface{})
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			requestParams[key] = values[0]
		}
	}
	if r.Method == http.MethodPost {
		var bodyData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&bodyData); err != nil {
			log.Printf("请求体解析错误: %v\n", err)
			http.Error(w, `{"error": "请求格式错误，请提供JSON数据"}`, http.StatusBadRequest)
			return
		}
		for key, value := range bodyData {
			requestParams[key] = value
		}
	}

	// 动态获取客户端凭证
	isAlipan := r.URL.Path == "/alipan-callback"
	var clientID, clientSecret string

	if isAlipan {
		clientID = getStringFromMap(requestParams, "client_id", config.Alipan.ClientID)
		clientSecret = getStringFromMap(requestParams, "client_secret", config.Alipan.ClientSecret)
	} else {
		clientID = getStringFromMap(requestParams, "client_id", config.OneDrive.ClientID)
		clientSecret = getStringFromMap(requestParams, "client_secret", config.OneDrive.ClientSecret)
	}

	if r.Method == http.MethodGet {
		if code := r.URL.Query().Get("code"); code != "" {
			handleAuthorizationCallback(w, r, redirectURI, isAlipan)
		} else {
			initAuthorizationFlow(w, r, clientID, clientSecret, redirectURI, isAlipan)
		}
	} else if r.Method == http.MethodPost {
		handleTokenRefresh(w, r, isAlipan)
	} else {
		http.Error(w, `{"error": "不支持的请求方法"}`, http.StatusMethodNotAllowed)
	}
}

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "config.json", "配置文件路径")
	flag.Parse()
	
	// 加载配置
	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	
	// 注册路由
	http.HandleFunc("/alipan-callback", handler)
	http.HandleFunc("/onedrive-callback", handler)
	
	// 添加更多启动信息
	log.Printf("配置文件: %s", *configPath)
	log.Printf("监听端口: %d", config.Server.Port)
	log.Printf("阿里云盘授权范围: %v", config.Alipan.Scope)
	log.Printf("OneDrive授权范围: %v", config.OneDrive.Scope)

	// 启动服务器
	log.Printf("服务器启动在 :%d\n", config.Server.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.Server.Port), nil))
}
