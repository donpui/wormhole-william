package wormhole

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"

	"github.com/psanford/wormhole-william/internal/crypto"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"

	"nhooyr.io/websocket"
)

/// TRANSPORT LAYERS

type transitConnection interface {
	// Write a framed message
	writeMsg(msg []byte) error

	// Read a framed message
	readMsg() ([]byte, error)

	// Handshake messages are known in size and contents by both sides. No framing necessary
	writeHandshakeMsg(msg []byte) error

	// Handshake messages are known in size and contents by both sides. Compare the read message with the expected one
	readHandshakeMsg(expected []byte) error

	Close() error
}

type tcpConnection struct {
	conn net.Conn
}

func (self *tcpConnection) writeMsg(msg []byte) error {
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(msg)))

	_, err := self.conn.Write(append(l, msg...))
	return err
}

func (self *tcpConnection) writeHandshakeMsg(msg []byte) error {
	_, err := self.conn.Write(msg)
	return err
}

func (self *tcpConnection) readMsg() ([]byte, error) {
	l := make([]byte, 4)
	_, err := io.ReadFull(self.conn, l)
	if err != nil {
		return nil, err
	}

	message := make([]byte, binary.BigEndian.Uint32(l))
	_, err = io.ReadFull(self.conn, message)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func (self *tcpConnection) readHandshakeMsg(expected []byte) error {
	read := make([]byte, len(expected))
	_, err := io.ReadFull(self.conn, read)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(read, expected) != 1 {
		return fmt.Errorf("not the same")
	}
	return nil
}

func (self *tcpConnection) Close() error {
	return self.conn.Close()
}

type wsConnection struct {
	conn    *websocket.Conn
	ctx     context.Context
	readBuf []byte
}

func (self *wsConnection) writeMsg(msg []byte) error {
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(msg)))
	return self.conn.Write(self.ctx, websocket.MessageBinary, append(l, msg...))
}

func (self *wsConnection) writeHandshakeMsg(msg []byte) error {
	return self.conn.Write(self.ctx, websocket.MessageBinary, msg)
}

func (self *wsConnection) readMsg() ([]byte, error) {
	/* Extract length prefix then read the message */
	lBuf, err := self.readExact(4)
	if err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint32(lBuf)

	return self.readExact(int(l))
}

func (self *wsConnection) readHandshakeMsg(expected []byte) error {
	msg, err := self.readExact(len(expected))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(msg, expected) != 1 {
		return fmt.Errorf("not the same")
	}
	return nil
}

/* Read exactly n bytes from the connection, no matter how they are split into WebSocket messages */
func (self *wsConnection) readExact(n int) ([]byte, error) {
	for len(self.readBuf) < n {
		msgType, msg, err := self.conn.Read(self.ctx)
		if err != nil {
			return nil, err
		}
		if msgType != websocket.MessageBinary {
			return nil, fmt.Errorf("got text message")
		}
		self.readBuf = append(self.readBuf, msg...)
	}
	msg := self.readBuf[:n]
	self.readBuf = self.readBuf[n:]
	return msg, nil
}

func (self *wsConnection) Close() error {
	return self.conn.Close(websocket.StatusNormalClosure, "")
}

/// INTERFACES

type transportCryptorInit interface {
	// Do the receiver handshake.
	// Write `conn` to `successChan` if the connection is to be used
	// Write addr to `failChan` on error
	directRecvHandshake(conn transitConnection, successChan chan transitConnection, failChan chan string, addr string)

	// Do the sender handshake, without confirming it to the receiver at the end
	// Write `conn` to `readyChan` if the handshake went through
	handleIncomingConnection(conn transitConnection, readyCh chan<- transitConnection, cancelCh chan struct{})

	// Finalize the sender handshake on the one connection to be used
	sendGo(conn transitConnection) error

	// Convert into a transportCryptor struct
	finalize(conn transitConnection, isLeader bool) transportCryptor
}

type transportCryptor interface {
	Close() error
	readRecord() ([]byte, error)
	writeRecord(msg []byte) error
}

/// CLASSIC

type transportCryptorInitClassic struct {
	transitKey []byte
}

func newTransportCryptorInitClassic(transitKey []byte) transportCryptorInit {
	return &transportCryptorInitClassic{
		transitKey: transitKey,
	}
}

func (t *transportCryptorInitClassic) senderHandshakeHeader() []byte {
	purpose := "transit_sender"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	return []byte(fmt.Sprintf("transit sender %x ready\n\n", out))
}

func (t *transportCryptorInitClassic) receiverHandshakeHeader() []byte {
	purpose := "transit_receiver"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	return []byte(fmt.Sprintf("transit receiver %x ready\n\n", out))
}

func (t *transportCryptorInitClassic) directRecvHandshake(conn transitConnection, successChan chan transitConnection, failChan chan string, addr string) {
	err := conn.readHandshakeMsg(t.senderHandshakeHeader())
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	err = conn.writeHandshakeMsg(t.receiverHandshakeHeader())
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	err = conn.readHandshakeMsg([]byte("go\n"))
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	successChan <- conn
}

func (t *transportCryptorInitClassic) handleIncomingConnection(conn transitConnection, readyCh chan<- transitConnection, cancelCh chan struct{}) {
	okCh := make(chan struct{})

	go func() {
		select {
		case <-cancelCh:
			conn.Close()
		case <-okCh:
		}
	}()

	err := conn.writeHandshakeMsg(t.senderHandshakeHeader())
	if err != nil {
		conn.Close()
		close(okCh)
		return
	}

	err = conn.readHandshakeMsg(t.receiverHandshakeHeader())
	if err != nil {
		conn.Close()
		close(okCh)
		return
	}

	select {
	case okCh <- struct{}{}:
	case <-cancelCh:
	}

	select {
	case <-cancelCh:
		// One of the other connections won, shut this one down
		conn.writeHandshakeMsg([]byte("nevermind\n"))
		conn.Close()
	case readyCh <- conn:
	}
}

func (t *transportCryptorInitClassic) sendGo(conn transitConnection) error {
	err := conn.writeHandshakeMsg([]byte("go\n"))
	return err
}

func (t *transportCryptorInitClassic) finalize(conn transitConnection, isLeader bool) transportCryptor {
	if isLeader {
		return newTransportCryptorClassic(conn, t.transitKey, "transit_record_receiver_key", "transit_record_sender_key")
	} else {
		return newTransportCryptorClassic(conn, t.transitKey, "transit_record_sender_key", "transit_record_receiver_key")
	}
}

type transportCryptorClassic struct {
	conn           transitConnection
	nextReadNonce  *big.Int
	nextWriteNonce uint64
	err            error
	readKey        [32]byte
	writeKey       [32]byte
}

func newTransportCryptorClassic(c transitConnection, transitKey []byte, readPurpose, writePurpose string) transportCryptor {
	r := hkdf.New(sha256.New, transitKey, nil, []byte(readPurpose))
	var readKey [32]byte
	_, err := io.ReadFull(r, readKey[:])
	if err != nil {
		panic(err)
	}

	r = hkdf.New(sha256.New, transitKey, nil, []byte(writePurpose))
	var writeKey [32]byte
	_, err = io.ReadFull(r, writeKey[:])
	if err != nil {
		panic(err)
	}

	return &transportCryptorClassic{
		conn:          c,
		nextReadNonce: big.NewInt(0),
		readKey:       readKey,
		writeKey:      writeKey,
	}
}
func (d *transportCryptorClassic) Close() error {
	return d.conn.Close()
}

func (d *transportCryptorClassic) readRecord() ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}

	msg, err := d.conn.readMsg()
	if err != nil {
		d.err = err
		return nil, d.err
	}

	var nonce [24]byte
	copy(nonce[:], msg[:len(nonce)])

	var bigNonce big.Int
	bigNonce.SetBytes(nonce[:])

	if bigNonce.Cmp(d.nextReadNonce) != 0 {
		d.err = errors.New("received out-of-order record")
		return nil, d.err
	}

	d.nextReadNonce.Add(d.nextReadNonce, big.NewInt(1))

	sealedMsg := msg[len(nonce):]

	out, ok := secretbox.Open(nil, sealedMsg, &nonce, &d.readKey)
	if !ok {
		d.err = errDecryptFailed
		return nil, d.err
	}

	return out, nil
}

func (d *transportCryptorClassic) writeRecord(msg []byte) error {
	var nonce [crypto.NonceSize]byte

	if d.nextWriteNonce == math.MaxUint64 {
		panic("Nonce exhaustion")
	}

	binary.BigEndian.PutUint64(nonce[crypto.NonceSize-8:], d.nextWriteNonce)
	d.nextWriteNonce++

	sealedMsg := secretbox.Seal(nonce[:], msg, &nonce, &d.writeKey)

	// we do an explit cast to int64 to avoid compilation failures
	// for 32bit systems.
	nonceAndSealedMsgSize := int64(len(sealedMsg))

	if nonceAndSealedMsgSize >= math.MaxUint32 {
		panic(fmt.Sprintf("writeRecord too large: %d", len(sealedMsg)))
	}

	return d.conn.writeMsg(sealedMsg)
}
