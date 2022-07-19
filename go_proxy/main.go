package main

import (
	"github.com/gorilla/mux"
	"github.com/im-zhou/GoHttpProxy/go_proxy/log"
	"github.com/im-zhou/GoHttpProxy/go_proxy/pkg"
	"net"
	"net/http"
)

func main() {
	log.InitLog("console", "logFile.log", "debug", 7, false)
	if err := pkg.InitClient(); err != nil { // 初始化Redis
		log.Error("Redis初始化错误:", err)
	}
	const addr = "0.0.0.0:443"
	log.Info("监听于 %s\n", addr)
	err := RunServer(addr)
	if err != nil {
		log.Error("监听http错误: %v", err)
		return
	}
}

func RunServer(address string) (err error) {
	var (
		cert = "fullchain.cer" // 证书文件名字 不需要使用os.Read
		key  = "private.key"
	)
	// url router
	router := mux.NewRouter()
	router.PathPrefix("/verify/{input}").HandlerFunc(pkg.VerifyAddress).Methods("GET")
	router.PathPrefix("/").HandlerFunc(pkg.ReqInterceptor).Methods("GET", "POST")
	if err := ListenAndServeTLS(address, router, cert, key); err != nil {
		return err
	}
	return nil
}

// 下面是重写Listen方法的，确保只会监听到ipv4
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func ListenAndServeTLS(addr string, handler http.Handler, certFile, keyFile string) error {
	srv := &http.Server{Addr: addr, Handler: handler}
	addr = srv.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp4", addr) // 仅指定 IPv4
	if err != nil {
		return err
	}
	return srv.ServeTLS(tcpKeepAliveListener{ln.(*net.TCPListener)}, certFile, keyFile)
}
