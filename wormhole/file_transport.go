package wormhole

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/psanford/wormhole-william/internal/crypto"
	"golang.org/x/crypto/hkdf"
	"nhooyr.io/websocket"
)

type fileTransportAck struct {
	Ack    string `json:"ack"`
	SHA256 string `json:"sha256"`
}

type TransferType int

const (
	TransferFile TransferType = iota + 1
	TransferDirectory
	TransferText
)

// Websocket read buffer size
const websocketReadSize int64 = 65536

// TCP direct connection timeout in sec.
const tcpDirectTimeout = 10

// UnsupportedProtocolErr is used in the default case of protocol switch
// statements to account for unexpected protocols.
var UnsupportedProtocolErr = errors.New("unsupported protocol")

func (tt TransferType) String() string {
	switch tt {
	case TransferFile:
		return "TransferFile"
	case TransferDirectory:
		return "TransferDirectory"
	case TransferText:
		return "TransferText"
	default:
		return fmt.Sprintf("TransferTypeUnknown<%d>", tt)
	}
}

func newFileTransport(transitKey []byte, appID string, relayURL *url.URL, disableListener bool) *fileTransport {
	return &fileTransport{
		transitKey:      transitKey,
		appID:           appID,
		relayURL:        relayURL,
		disableListener: disableListener,
		cryptorInit:     newTransportCryptorInitClassic(transitKey),
	}
}

type fileTransport struct {
	disableListener bool
	listener        net.Listener
	relayConn       transitConnection
	relayURL        *url.URL
	transitKey      []byte
	cryptorInit     transportCryptorInit
	appID           string
}

func (t *fileTransport) connectViaRelay(otherTransit *transitMsg, transitKey []byte) (transportCryptor, error) {
	successChan := make(chan transitConnection)
	failChan := make(chan string)

	var count int

	for _, relay := range otherTransit.HintsV1 {
		if relay.Type == "relay-v1" {
			for _, endpoint := range relay.Hints {
				var relayUrl *url.URL
				var err error

				switch endpoint.Type {
				case "direct-tcp-v1":
					relayUrl = &url.URL{
						Scheme: "tcp",
						Host:   net.JoinHostPort(endpoint.Hostname, strconv.Itoa(endpoint.Port)),
					}
				case "websocket-v1":
					relayUrl, err = url.Parse(endpoint.Url)

				}
				ctx, cancel := context.WithCancel(context.Background())

				//in case invalid url, cancel download
				if err == nil {
					count++
					go t.connectToRelay(ctx, relayUrl, successChan, failChan)
				} else {
					cancel()
					continue
				}
			}
		}
	}

	var conn transitConnection

	for i := 0; i < count; i++ {
		select {
		case <-failChan:
		case conn = <-successChan:
		}
	}

	if conn == nil {
		return nil, nil
	}

	return t.cryptorInit.finalize(conn, false), nil
}

func (t *fileTransport) connectDirect(otherTransit *transitMsg, transitKey []byte) (transportCryptor, error) {
	cancelFuncs := make(map[string]func())

	successChan := make(chan transitConnection)
	failChan := make(chan string)

	var count int

	for _, hint := range otherTransit.HintsV1 {
		if hint.Type == "direct-tcp-v1" {
			count++
			// set timeout, how long we wait for TCP direct connection to accept, not to hang forever
			ctx, cancel := context.WithTimeout(context.Background(), tcpDirectTimeout*time.Second)
			addr := net.JoinHostPort(hint.Hostname, strconv.Itoa(hint.Port))

			cancelFuncs[addr] = cancel

			go t.connectToSingleHost(ctx, addr, successChan, failChan)
		}
	}

	var conn transitConnection

	for i := 0; i < count; i++ {
		select {
		case <-failChan:
		case conn = <-successChan:
		}
	}

	if conn == nil {
		return nil, nil
	}

	return t.cryptorInit.finalize(conn, false), nil
}

func (t *fileTransport) connectToRelay(ctx context.Context, relayUrl *url.URL, successChan chan transitConnection, failChan chan string) {
	var d net.Dialer
	var conn transitConnection
	var err error

	//in case address is not provide in hints, try default
	if relayUrl == nil {
		relayUrl.Scheme = t.relayURL.Scheme
		relayUrl.Host = t.relayURL.Host
	}

	switch relayUrl.Scheme {
	case "tcp":
		connRaw, err := d.DialContext(ctx, relayUrl.Scheme, relayUrl.Host)
		if err != nil {
			failChan <- relayUrl.String()
			return
		}
		conn = &tcpConnection{conn: connRaw}
		fmt.Println("Downloading... via TCP relay " + relayUrl.String())
	case "ws", "wss":
		var wsconn *websocket.Conn
		wsconn, _, err = websocket.Dial(ctx, relayUrl.String(), nil)
		if err != nil {
			failChan <- relayUrl.String()
			return
		}
		wsconn.SetReadLimit(websocketReadSize)
		fmt.Println("Downloading... via WebSocket relay " + relayUrl.String())
		// conn = websocket.NetConn(ctx, wsconn, websocket.MessageBinary)
		conn = &wsConnection{conn: *wsconn, ctx: ctx}
	}

	err = conn.writeHandshakeMsg(t.relayHandshakeHeader())
	if err != nil {
		failChan <- relayUrl.String()
		return
	}
	err = conn.readHandshakeMsg([]byte("ok\n"))
	if err != nil {
		conn.Close()
		failChan <- relayUrl.String()
		return
	}

	t.cryptorInit.directRecvHandshake(conn, successChan, failChan, relayUrl.Host)
}

func (t *fileTransport) connectToSingleHost(ctx context.Context, addr string, successChan chan transitConnection, failChan chan string) {
	var d net.Dialer
	fmt.Println("Downloading... directly")
	conn, err := d.DialContext(ctx, "tcp", addr)

	if err != nil {
		failChan <- addr
		return
	}

	t.cryptorInit.directRecvHandshake(&tcpConnection{conn: conn}, successChan, failChan, addr)
}

func (t *fileTransport) makeTransitMsg() (*transitMsg, error) {
	msg := transitMsg{
		AbilitiesV1: []transitAbility{
			{
				Type: "direct-tcp-v1",
			},
			{
				Type: "relay-v1",
			},
		},
		// make a slice so this jsons to [] and not null
		HintsV1: make([]transitHintsV1, 0),
	}

	if t.listener != nil {
		_, portStr, err := net.SplitHostPort(t.listener.Addr().String())
		if err != nil {
			return nil, err
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("port isn't an integer? %s", portStr)
		}

		addrs := nonLocalhostAddresses()

		for _, addr := range addrs {
			msg.HintsV1 = append(msg.HintsV1, transitHintsV1{
				Type:     "direct-tcp-v1",
				Priority: 0.0,
				Hostname: addr,
				Port:     port,
			})
		}
	}

	if t.relayConn != nil {
		var relayType string
		switch t.relayURL.Scheme {
		case "tcp":
			relayType = "direct-tcp-v1"
		case "ws":
			relayType = "websocket-v1"
		case "wss":
			relayType = "websocket-v1"
		default:
			return nil, fmt.Errorf("%w: '%s'", UnsupportedProtocolErr, t.relayURL.Scheme)
		}
		if relayType == "direct-tcp-v1" {
			var port, err = strconv.Atoi(t.relayURL.Port())
			if err != nil {
				return nil, fmt.Errorf("invalid port")
			}
			msg.HintsV1 = append(msg.HintsV1, transitHintsV1{
				Type: "relay-v1",
				Hints: []transitHintsRelay{
					{
						Type:     relayType,
						Hostname: t.relayURL.Hostname(),
						Port:     port,
					},
				},
			})
		} else {
			msg.HintsV1 = append(msg.HintsV1, transitHintsV1{
				Type: "relay-v1",
				Hints: []transitHintsRelay{
					{
						Type: relayType,
						Url:  t.relayURL.String(),
					},
				},
			})
		}
	}

	return &msg, nil
}

func (t *fileTransport) relayHandshakeHeader() []byte {
	purpose := "transit_relay_token"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	sideID := crypto.RandHex(8)

	return []byte(fmt.Sprintf("please relay %x for side %s\n", out, sideID))
}

func (t *fileTransport) listen() error {
	if t.disableListener {
		return nil
	}
	// always have tcp listener, otherwise app should run with --no-listen
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	t.listener = l

	return nil
}

func (t *fileTransport) listenRelay() (err error) {
	ctx := context.Background()

	var conn transitConnection
	switch t.relayURL.Scheme {
	case "tcp":
		// NB: don't dial the relay if we don't have an address.
		// NB2: Host already contains the port here, if present
		addr := t.relayURL.Host
		if addr == "" {
			return nil
		}

		tcpconn, err := net.Dial("tcp", addr)
		if err != nil {
			return err
		}
		conn = &tcpConnection{conn: tcpconn}
	case "ws", "wss":
		c, _, err := websocket.Dial(ctx, t.relayURL.String(), nil)
		if err != nil {
			return fmt.Errorf("websocket.Dial failed")
		}
		c.SetReadLimit(websocketReadSize)
		//conn = websocket.NetConn(ctx, c, websocket.MessageBinary)
		conn = &wsConnection{conn: *c, ctx: ctx}
	default:
		return fmt.Errorf("%w: '%s'", UnsupportedProtocolErr, t.relayURL.Scheme)
	}

	err = conn.writeHandshakeMsg(t.relayHandshakeHeader())
	if err != nil {
		conn.Close()
		return err
	}

	t.relayConn = conn
	return nil
}

func (t *fileTransport) waitForRelayPeer(conn transitConnection, cancelCh chan struct{}) error {
	okCh := make(chan struct{})
	go func() {
		select {
		case <-cancelCh:
			conn.Close()
		case <-okCh:
		}
	}()

	defer close(okCh)

	err := conn.readHandshakeMsg([]byte("ok\n"))
	if err != nil {
		conn.Close()
		return err
	}

	return nil
}

func (t *fileTransport) acceptConnection(ctx context.Context, transitKey []byte) (transportCryptor, error) {
	readyCh := make(chan transitConnection)
	cancelCh := make(chan struct{})
	acceptErrCh := make(chan error, 1)

	if t.relayConn != nil {
		go func() {
			waitErr := t.waitForRelayPeer(t.relayConn, cancelCh)
			if waitErr != nil {
				return
			}
			t.cryptorInit.handleIncomingConnection(t.relayConn, readyCh, cancelCh)
		}()
	}

	if t.listener != nil {
		defer t.listener.Close()

		go func() {
			for {
				connRaw, err := t.listener.Accept()
				if err == io.EOF {
					break
				} else if err != nil {
					acceptErrCh <- err
					break
				}
				conn := &tcpConnection{conn: connRaw}

				go t.cryptorInit.handleIncomingConnection(conn, readyCh, cancelCh)
			}
		}()
	}

	select {
	case <-ctx.Done():
		close(cancelCh)
		return nil, ctx.Err()
	case acceptErr := <-acceptErrCh:
		close(cancelCh)
		return nil, acceptErr
	case conn := <-readyCh:
		close(cancelCh)
		err := t.cryptorInit.sendGo(conn)
		if err != nil {
			return nil, err
		}

		return t.cryptorInit.finalize(conn, true), nil
	}
}

func nonLocalhostAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	var outAddrs []string

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				outAddrs = append(outAddrs, ipnet.IP.String())
			}
		}
	}

	return outAddrs
}
