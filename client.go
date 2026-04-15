package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServerURL  string   `json:"server_url"`
	ListenAddr string   `json:"listen_addr"`
	Whitelist  []string `json:"whitelist"`
}

var (
	whitelist  []string
	serverURL  string
	listenAddr string
)

func isWhitelisted(domain string) bool {
	for _, w := range whitelist {
		if domain == w || strings.HasSuffix(domain, "."+w) {
			return true
		}
	}
	return false
}

func loadConfig() {
	cfgFile := "config.json"
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		fmt.Println("[\u26A0\uFE0F] Файл config.json не найден. Давайте настроим подключение.")
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("[?] Введите IP и порт вашего сервера (например, 1.2.3.4:8080): ")
		inputUrl, _ := reader.ReadString('\n')
		inputUrl = strings.TrimSpace(inputUrl)
		if inputUrl == "" {
			inputUrl = "1.2.3.4:8080"
			fmt.Println("    Использован сервер по умолчанию:", inputUrl)
		}

		cfg := Config{
			ServerURL:  inputUrl,
			ListenAddr: "127.0.0.1:1080",
			Whitelist:  []string{"yandex.ru", "vk.com", "mail.ru", "gosuslugi.ru"},
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		os.WriteFile(cfgFile, b, 0644)
		serverURL = cfg.ServerURL
		listenAddr = cfg.ListenAddr
		whitelist = cfg.Whitelist
		fmt.Println("[\u2705] Конфигурационный файл 'config.json' успешно сохранен.")
	} else {
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Ошибка парсинга config.json: %v", err)
		}
		serverURL = cfg.ServerURL
		listenAddr = cfg.ListenAddr
		whitelist = cfg.Whitelist
		fmt.Println("[\u2705] Настройки успешно загружены из config.json")
	}
}

func main() {
	fmt.Println("=======================================")
	fmt.Println("\U0001f680 Secure Proxy Client - Запуск...")
	
	loadConfig()

	// Optionally override via flags if needed
	flag.StringVar(&serverURL, "server", serverURL, "Address of the remote proxy server")
	flag.StringVar(&listenAddr, "listen", listenAddr, "Local SOCKS5 listen address")
	flag.Parse()
	
	fmt.Println("=======================================")
	fmt.Printf("[\u25B6] Удаленный сервер:  %s\n", serverURL)
	fmt.Printf("[\u25B6] Локальный прокси:  %s (SOCKS5)\n", listenAddr)
	fmt.Printf("[\u25B6] Белый список:      %d доменов\n", len(whitelist))
	fmt.Println("=======================================")
	fmt.Println("[\u2139\uFE0F] Как использовать:")
	fmt.Println("    1. Откройте настройки браузера или мессенджера (например, Telegram).")
	fmt.Println("    2. Выберите тип прокси: SOCKS5")
	fmt.Println("    3. Укажите адрес '127.0.0.1' и порт '1080'.")
	fmt.Println("       (Рекомендуем использовать расширения, например SwitchyOmega)")
	fmt.Println("=======================================")
	fmt.Println("[\u2714] Программа готова к работе! Сверните окно, но не закрывайте.")
	fmt.Println("    Для остановки сервера нажмите Ctrl+C.")
	fmt.Println("---------------------------------------")

	addr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Invalid listen address: %v", err)
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("Local SOCKS5 proxy running on %s", listenAddr)
	log.Printf("Remote server set to: %s", serverURL)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept err: %v", err)
			continue
		}
		go handleSocks5(conn)
	}
}

func handleSocks5(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 256)

	// Hello Phase
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		log.Println("Unsupported protocol. Only SOCKS5.")
		return
	}
	numMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:numMethods]); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // NO AUTH

	// Request Phase
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 { // Only CONNECT
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atyp := buf[3]
	var dest string
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		io.ReadFull(conn, ip)
		dest = net.IP(ip).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		domain := make([]byte, int(lenBuf[0]))
		io.ReadFull(conn, domain)
		dest = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		io.ReadFull(conn, ip)
		dest = net.IP(ip).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	io.ReadFull(conn, portBuf)
	port := binary.BigEndian.Uint16(portBuf)

	destAddress := net.JoinHostPort(dest, strconv.Itoa(int(port)))

	var remoteConn net.Conn
	var err error

	if isWhitelisted(dest) {
		log.Printf("Direct connection: %s", destAddress)
		remoteConn, err = net.DialTimeout("tcp", destAddress, 10*time.Second)
	} else {
		log.Printf("Tunneling: %s -> %s", destAddress, serverURL)
		remoteConn, err = dialTunnel(serverURL, destAddress)
	}

	if err != nil {
		log.Printf("Dial failed for %s: %v", destAddress, err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer remoteConn.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Success

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(remoteConn, conn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(conn, remoteConn)
		errc <- err
	}()
	<-errc
}

func dialTunnel(serverAddr string, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", serverAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	key := make([]byte, 16)
	rand.Read(key)
	b64Key := base64.StdEncoding.EncodeToString(key)

	// Send target embedded inside standard Sec-WebSocket-Protocol header to pass DPI heuristics safely
	encodedTarget := base64.StdEncoding.EncodeToString([]byte(target))

	req := fmt.Sprintf("GET /stream HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Protocol: %s\r\n\r\n", serverAddr, b64Key, encodedTarget)

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	buf := make([]byte, 4096)
	reqStr := ""
	for {
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			return nil, err
		}
		reqStr += string(buf[:n])
		if strings.Contains(reqStr, "\r\n\r\n") {
			break
		}
	}

	if !strings.Contains(reqStr, "101 Switching Protocols") {
		conn.Close()
		return nil, fmt.Errorf("invalid server handshake response")
	}

	return &wsConn{conn: conn, isClient: true}, nil
}

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
	header = append(header, 0x82) // FIN + Binary

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
