package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	pauseUntil time.Time
	mu         sync.RWMutex
)

func isPaused() bool {
	mu.RLock()
	defer mu.RUnlock()
	return time.Now().Before(pauseUntil)
}

func triggerCanary(port string) {
	mu.Lock()
	defer mu.Unlock()
	log.Printf("!!! Canary triggered on port %s! Pausing main proxy for 5 seconds !!!", port)
	pauseUntil = time.Now().Add(5* time.Second)
}

func startCanary(port string) {
	l, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Fatalf("Failed to start canary on port %s: %v", port, err)
	}
	log.Printf("Canary port listening on %s", port)
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			triggerCanary(port)
			// Simulate a dummy service banner like SSH to delay the scanner
			c.Write([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"))
			time.Sleep(2 * time.Second)
			c.Close()
		}(conn)
	}
}

func main() {
	mainPort := flag.String("port", "8080", "Main proxy listener port")
	canaryPort1 := flag.String("canary1", "8079", "First canary port")
	canaryPort2 := flag.String("canary2", "8081", "Second canary port")
	flag.Parse()

	go startCanary(*canaryPort1)
	go startCanary(*canaryPort2)

	l, err := net.Listen("tcp", "0.0.0.0:"+*mainPort)
	if err != nil {
		log.Fatalf("Failed to listen on main port %s: %v", *mainPort, err)
	}
	
	log.Println("=======================================")
	log.Println("🚀 Secure Proxy Server - Запущен!")
	log.Printf("▶ Главный порт:   %s", *mainPort)
	log.Printf("▶ Fake-порт 1:    %s (Канарейка)", *canaryPort1)
	log.Printf("▶ Fake-порт 2:    %s (Канарейка)", *canaryPort2)
	log.Println("=======================================")
	log.Println("ℹ️  Используйте IP этого сервера и Главный порт")
	log.Println("   для настройки клиента (client.go / config.json).")
	log.Println("   Для остановки нажмите Ctrl+C.")
	log.Println("---------------------------------------")

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}

		if isPaused() {
			log.Printf("Connection from %s dropped (proxy paused due to canary scan)", conn.RemoteAddr())
			conn.Close()
			continue
		}

		go handleServerConn(conn)
	}
}

func handleServerConn(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 4096)
	var reqStr string
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		reqStr += string(buf[:n])
		if strings.Contains(reqStr, "\r\n\r\n") {
			break
		}
	}

	conn.SetReadDeadline(time.Time{})

	if !strings.HasPrefix(reqStr, "GET /stream HTTP/1.1") {
		// Not our custom WebSocket handshake
		log.Printf("Invalid HTTP handshake from %s, dropping connection", conn.RemoteAddr())
		return
	}

	lines := strings.Split(reqStr, "\r\n")
	var key, encodedTarget string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "sec-websocket-key:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(lower, "sec-websocket-protocol:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				encodedTarget = strings.TrimSpace(parts[1])
			}
		}
	}

	if key == "" || encodedTarget == "" {
		return
	}

	decodedTarget, err := base64.StdEncoding.DecodeString(encodedTarget)
	if err != nil {
		return
	}
	targetAddr := string(decodedTarget)
	log.Printf("Proxying request to %s", targetAddr)

	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n"+
		"Sec-WebSocket-Protocol: %s\r\n\r\n", acceptKey, encodedTarget)

	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to dial target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	ws := &wsConn{conn: conn, isClient: false}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(ws, targetConn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(targetConn, ws)
		errc <- err
	}()
	<-errc
}

// Reusable custom websocket framer implementation identical to the client 
type wsConn struct {
	conn     net.Conn
	readBuf  []byte
	isClient bool
}

func (w *wsConn) Read(b []byte) (n int, err error) {
	if len(w.readBuf) > 0 {
		n = copy(b, w.readBuf)
		w.readBuf = w.readBuf[n:]
		return n, nil
	}

	header := make([]byte, 2)
	_, err = io.ReadFull(w.conn, header)
	if err != nil {
		return 0, err
	}

	opcode := header[0] & 0x0F
	if opcode == 0x08 {
		return 0, io.EOF
	}

	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7F)

	if payloadLen == 126 {
		extLen := make([]byte, 2)
		io.ReadFull(w.conn, extLen)
		payloadLen = int(binary.BigEndian.Uint16(extLen))
	} else if payloadLen == 127 {
		extLen := make([]byte, 8)
		io.ReadFull(w.conn, extLen)
		payloadLen = int(binary.BigEndian.Uint64(extLen))
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		io.ReadFull(w.conn, maskKey)
	}

	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(w.conn, payload)
	if err != nil {
		return 0, err
	}

	if masked {
		for i := 0; i < payloadLen; i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	n = copy(b, payload)
	if n < payloadLen {
		w.readBuf = payload[n:]
	}
	return n, nil
}

func (w *wsConn) Write(b []byte) (n int, err error) {
	var header []byte
	header = append(header, 0x82)

	l := len(b)
	maskBit := byte(0)
	if w.isClient {
		maskBit = 0x80
	}

	if l < 126 {
		header = append(header, maskBit|byte(l))
	} else if l <= 65535 {
		header = append(header, maskBit|126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(l))
		header = append(header, ext...)
	} else {
		header = append(header, maskBit|127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(l))
		header = append(header, ext...)
	}

	var mask []byte
	if w.isClient {
		mask = make([]byte, 4)
		rand.Read(mask)
		header = append(header, mask...)
	}

	_, err = w.conn.Write(header)
	if err != nil {
		return 0, err
	}

	if w.isClient {
		maskedPayload := make([]byte, l)
		for i := 0; i < l; i++ {
			maskedPayload[i] = b[i] ^ mask[i%4]
		}
		_, err = w.conn.Write(maskedPayload)
	} else {
		_, err = w.conn.Write(b)
	}

	if err != nil {
		return 0, err
	}
	return l, nil
}

func (w *wsConn) Close() error                     { return w.conn.Close() }
func (w *wsConn) LocalAddr() net.Addr              { return w.conn.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr             { return w.conn.RemoteAddr() }
func (w *wsConn) SetDeadline(t time.Time) error    { return w.conn.SetDeadline(t) }
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }
