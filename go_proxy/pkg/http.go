package pkg

import (
	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/im-zhou/GoHttpProxy/go_proxy/log"

	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const NotVerify = `
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8" />
<title>401 访问未授权</title>
</head>
<body>
<h1>401 访问未授权</h1>
<h3>不要在此页面或未通过验证的域名频繁刷新，您的IP可能会被封禁，如果误封，请联系群管理解除</h3>
<h3>不管是否通过授权，如果程序检测到恶意请求，您的IP会被封禁，如果误封，请联系群管理解除</h3>
<h3><a href="https://jq.qq.com/?_wv=1027&k=GHF8NZdC">OpenFRP用户交流群，点击加群</a></h3>
<span style="color: red"> Hey 你需要回答正确的问题噢</span>
<div>
<label for="dev_name">dev站的主要开发者是谁?</label><br/>
<input type="text" name="dev_name" id="dev_name" /> <br/>
<button onclick="window.location.href = '/verify/' + document.getElementById('dev_name').value" 
	type="button" id="submit">提交</button>
</div>
</body>
</html>
`

func banIP(ipAddr string) {
	var cmd string
	cmd = "iptables -L -v -n"
	log.Info("执行命令: %v", cmd)
	c1 := exec.Command("/bin/sh", "-c", cmd)
	if result, err := c1.Output(); err != nil {
		log.Warn("系统命令执行出错1: %v", err)
	} else {
		//log.Info("查询结果: %v \n", string(result))
		if !strings.Contains(string(result), ipAddr) {
			cmd = "iptables -I INPUT -s " + ipAddr + " -j DROP"
			log.Info("执行命令: %v", cmd)
			c2 := exec.Command("/bin/sh", "-c", cmd)
			if err := c2.Run(); err != nil {
				log.Warn("系统命令执行出错2: %v", err)
			}
		} else {
			log.Debug("已经ban的IP: ", ipAddr)
		}
	}
}

func defenseCC(ipAddr string) {
	// 防御策略, 5s 内请求达100 封禁IP
	var reqCount = Rdb.Get(ipAddr + "_req_times").Val()
	if reqCount != "" {
		val, _ := strconv.Atoi(reqCount)
		Rdb.Set(ipAddr+"_req_times", val+1, 5*time.Second)
	} else {
		Rdb.Set(ipAddr+"_req_times", 1, 5*time.Second)
	}
	if val, _ := strconv.Atoi(reqCount); val > 100 {
		banIP(ipAddr)
	}
}

func ReqInterceptor(w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Server")
	w.Header().Set("Server", "OpenFRP GO HTTP Server")
	var remoteAddr = r.RemoteAddr
	if len(strings.Split(remoteAddr, ":")) >= 1 {
		remoteAddr = strings.Split(remoteAddr, ":")[0]
	}
	defenseCC(remoteAddr)
	var reqDomain = Rdb.Get(remoteAddr).Val()
	//log.Info(remoteAddr + " Redis查询值: " + reqDomain + " 请求URL: " + r.Host + r.RequestURI)
	if reqDomain != "" && reqDomain == r.Host {
		r.Header.Set("CLIENT_IP", remoteAddr) // 自定义标头 nginx需要设置 underscores_in_headers on; 变量为 $HTTP_CLIENT_IP
		r.Header.Set("Host", r.Host)
		log.Info(remoteAddr + " 放行,请求URL: " + r.Host + r.RequestURI)
		u, _ := url.Parse("http://127.0.0.1:8080/")
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.ServeHTTP(w, r)
	} else {
		var reqCount = Rdb.Get(remoteAddr + "_req_count").Val()
		if reqCount != "" {
			val, _ := strconv.Atoi(reqCount)
			Rdb.Set(remoteAddr+"_req_count", val+1, 600*time.Second)
		} else {
			Rdb.Set(remoteAddr+"_req_count", 1, 600*time.Second)
		}
		val, _ := strconv.Atoi(reqCount)
		if val > 50 { // 请求的域名不存在 > 50 次时 封禁IP
			banIP(remoteAddr)
		}
		log.Info(remoteAddr+" 未授权，已拦截 "+r.Host+r.RequestURI+" 计数: %v", val)
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte(NotVerify))
		return
	}
}

func VerifyAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Del("Server")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache") // 设置缓存标记，确保浏览器不会缓存
	w.Header().Set("Expires", "0")
	w.Header().Set("Server", "OpenFRP GO HTTP Server")
	//r.ParseForm() // 解析参数，默认是不会解析的
	params := mux.Vars(r)
	input := params["input"]
	log.Info(r.RemoteAddr + " 输入 " + input)
	var key = r.RemoteAddr
	if len(strings.Split(key, ":")) >= 1 {
		key = strings.Split(key, ":")[0]
	}
	if input == "zhou" {
		if Rdb.Get(key).Val() != "" {
			log.Info(" 有效的会话")
			http.Redirect(w, r, "//"+Rdb.Get(key).Val(), http.StatusMovedPermanently)
			return
		}
		var randomUuid, err = uuid.NewV4()
		if err != nil {
			log.Error("UUID 新建错误: ", err)
			return
		}
		var val = strings.ReplaceAll(key, ".", "-") + "-" + randomUuid.String() + ".of-dev.bfsea.xyz"
		result, err := Rdb.Set(key, val, 30*time.Minute).Result()
		if err != nil {
			log.Error(" Redis Set 错误: %v", err)
			return
		}
		log.Info(key + " Redis结果: " + result + " 发送重定向: " + val)
		http.Redirect(w, r, "//"+val, http.StatusMovedPermanently)
		return
	} else {
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte(`
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8" />
<title>401 访问未授权</title>
</head>
<body>
<span style="color: red"> 回答不正确</span>
</body>
</html>`))
		return
	}
}
