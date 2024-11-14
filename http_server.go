package main

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/polevpn/elog"
)

const (
	TCP_WRITE_BUFFER_SIZE = 524288
	TCP_READ_BUFFER_SIZE  = 524288
	READ_BUFFER_SIZE      = 2048
)

type UserTraffic struct {
	traffic   uint64
	startTime time.Time
}

type HttpServer struct {
	loginchecker LoginChecker
	upgrader     *websocket.Upgrader
	trafficMap   map[string]*UserTraffic
	rwMutex      *sync.RWMutex
}

func NewHttpServer() *HttpServer {

	upgrader := &websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		EnableCompression: false,
	}

	return &HttpServer{
		upgrader:   upgrader,
		trafficMap: make(map[string]*UserTraffic, 0),
		rwMutex:    &sync.RWMutex{},
	}
}

func (hs *HttpServer) SetLoginCheckHandler(loginchecker LoginChecker) {
	hs.loginchecker = loginchecker
}

func (hs *HttpServer) defaultHandler(w http.ResponseWriter, r *http.Request) {
	hs.respError(http.StatusForbidden, w)
}

func (hs *HttpServer) ListenTLS(addr string, certFile string, keyFile string) error {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			hs.wsHandler(w, r)
		} else {
			hs.defaultHandler(w, r)
		}
	})

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}
	return server.ListenAndServeTLS(certFile, keyFile)
}

func (hs *HttpServer) respError(status int, w http.ResponseWriter) {

	w.Header().Add("Server", "nginx/1.10.3")
	w.WriteHeader(status)
	resp := fmt.Sprintf("<html>\n<head><title>%v %v</title></head>\n<body bgcolor=\"white\">\n<center><h1>%v %v</h1></center>\n<hr><center>nginx/1.10.3</center>\n</body>\n</html>", status, http.StatusText(status), status, http.StatusText(status))
	w.Write([]byte(resp))
}

func (hs *HttpServer) copyStream(user string, dst net.Conn, src net.Conn, waitTime time.Duration, limitTraffic uint64, wg *sync.WaitGroup) (n int64) {
	defer wg.Done()

	buf := make([]byte, READ_BUFFER_SIZE)

	for {
		if waitTime > 0 {
			src.SetReadDeadline(time.Now().Add(waitTime))
		}
		nr, err := src.Read(buf)

		if nr > 0 {
			if nw, err := dst.Write(buf[:nr]); err != nil {
				elog.Debugf(err.Error())
				break
			} else {
				n += int64(nw)
			}
		}

		bytes, duration := hs.limitTraffic(user, uint64(nr))
		if bytes > limitTraffic/20 {
			if duration > 0 {
				time.Sleep(duration)
			}
		}

		if err != nil {
			elog.Debugf(err.Error())
			break
		}
	}
	return
}

func (hs *HttpServer) handleTCP(w http.ResponseWriter, r *http.Request) {

	user, token, dst, port, proto := hs.getHeaderParams(r)

	if !hs.loginchecker.CheckToken(user, token) {
		elog.Errorf("user:%v,token:%v verify fail", user, token)
		hs.respError(http.StatusForbidden, w)
		return
	}

	conn, err := hs.upgrader.Upgrade(w, r, nil)
	if err != nil {
		elog.Errorf("user:%v,proto:%v,dst:%v,port:%v upgrade fail,%v", user, proto, dst, port, err)
		hs.respError(http.StatusBadRequest, w)
		return
	}

	elog.Infof("user:%v,proto:%v,dst:%v,port:%v,conn:%v", user, proto, dst, port, conn.RemoteAddr().String())

	wsconn := NewWSStreamConn(conn)

	defer wsconn.Close()

	rconn, err := net.DialTimeout("tcp", dst+":"+port, time.Millisecond*time.Duration(Config.Get("proxy_connect_timeout").AsInt(5000)))
	if err != nil {
		elog.Errorf("user:%v,proto:%v,dst:%v,port:%v tcp connect fail,%v", user, proto, dst, port, err)
		hs.respError(http.StatusInternalServerError, w)
		return
	}

	defer rconn.Close()

	wg := &sync.WaitGroup{}

	wg.Add(2)

	var upBytes, downBytes int64

	go func() {
		upBytes = hs.copyStream(user, rconn, wsconn, time.Millisecond*time.Duration(Config.Get("proxy_read_timeout").AsInt(60000)), Config.Get("upstream_traffic_limit").AsUint64(100000), wg)
	}()

	go func() {
		downBytes = hs.copyStream(user, wsconn, rconn, time.Millisecond*time.Duration(Config.Get("proxy_read_timeout").AsInt(60000)), Config.Get("downstream_traffic_limit").AsUint64(100000), wg)
	}()

	wg.Wait()

	elog.Infof("user:%v,proto:%v,dst:%v,port:%v,up:%v,down:%v", user, proto, dst, port, upBytes, downBytes)

}

func (hs *HttpServer) getHeaderParams(r *http.Request) (user string, token string, dst string, port string, proto string) {

	user = r.Header.Get("User")
	token = r.Header.Get("Token")

	dst = r.Header.Get("Dst")
	port = r.Header.Get("Port")
	proto = r.Header.Get("Proto")

	return
}

func (hs *HttpServer) handleUDP(w http.ResponseWriter, r *http.Request) {

	user, token, dst, port, proto := hs.getHeaderParams(r)

	if !hs.loginchecker.CheckToken(user, token) {
		elog.Errorf("user:%v,token:%v verify fail", user, token)
		hs.respError(http.StatusForbidden, w)
		return
	}

	conn, err := hs.upgrader.Upgrade(w, r, nil)
	if err != nil {
		elog.Errorf("user:%v,proto:%v,dst:%v,port:%v upgrade fail,%v", user, proto, dst, port, err)
		hs.respError(http.StatusBadRequest, w)
		return
	}

	elog.Infof("user:%v,proto:%v,dst:%v,port:%v,conn:%v", user, proto, dst, port, conn.RemoteAddr().String())

	wsconn := NewWSMessageConn(conn)

	defer wsconn.Close()

	rconn, err := net.Dial("udp", dst+":"+port)

	if err != nil {
		elog.Errorf("user:%v,proto:%v,dst:%v,port:%v udp connect fail,%v", user, proto, dst, port, err)
		hs.respError(http.StatusInternalServerError, w)
		return
	}

	defer rconn.Close()

	wg := &sync.WaitGroup{}

	wg.Add(2)

	var upBytes, downBytes int64

	go func() {
		upBytes = hs.copyStream(user, rconn, wsconn, time.Millisecond*time.Duration(Config.Get("proxy_read_timeout").AsInt(60000)), Config.Get("upstream_traffic_limit").AsUint64(100000), wg)
	}()

	go func() {
		downBytes = hs.copyStream(user, wsconn, rconn, time.Millisecond*time.Duration(Config.Get("proxy_read_timeout").AsInt(60000)), Config.Get("downstream_traffic_limit").AsUint64(100000), wg)
	}()

	wg.Wait()

	elog.Infof("user:%v,proto:%v,dst:%v,port:%v,up:%v,down:%v", user, proto, dst, port, upBytes, downBytes)

}

func (hs *HttpServer) handleAUTH(w http.ResponseWriter, r *http.Request) {

	user := r.Header.Get("User")
	pwd := r.Header.Get("Pwd")

	auth, err := hs.loginchecker.Auth(user, pwd)

	if err != nil {
		elog.Errorf("user %v,auth fail,%v", user, err)
		hs.respError(http.StatusForbidden, w)
		return
	}

	data, _ := auth.EncodeJson()

	w.Write(data)

}

func (hs *HttpServer) wsHandler(w http.ResponseWriter, r *http.Request) {

	defer PanicHandler()

	proto := r.Header.Get("Proto")

	if proto == "tcp" {
		hs.handleTCP(w, r)
	} else if proto == "udp" {
		hs.handleUDP(w, r)
	} else if proto == "auth" {
		hs.handleAUTH(w, r)
	} else {
		elog.Errorf("invalid proto:%v", proto)
		hs.respError(http.StatusForbidden, w)
	}

}

func (hs *HttpServer) limitTraffic(user string, traffic uint64) (uint64, time.Duration) {

	hs.rwMutex.RLock()
	tf := hs.trafficMap[user]
	hs.rwMutex.RUnlock()

	nowTime := time.Now()
	if tf == nil { //30  0.1
		tf = &UserTraffic{traffic, nowTime}
		hs.rwMutex.Lock()
		hs.trafficMap[user] = tf
		hs.rwMutex.Unlock()
	}

	if nowTime.Sub(tf.startTime) > 50*time.Millisecond {
		tf.traffic = 0
		tf.startTime = nowTime
	}

	atomic.AddUint64(&tf.traffic, traffic)

	return tf.traffic, 50*time.Millisecond - nowTime.Sub(tf.startTime)

}
