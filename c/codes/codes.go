package codes

type Code int

const (
	ERR_UNKNOWN = Code(iota) - 1
	OK
	ERR_NO_CLIENT
	ERR_SEND_TEXT
	ERR_SEND_TEXT_RESULT
	ERR_RECV_TEXT
	ERR_RECV_TEXT_DATA
	ERR_SEND_FILE
	ERR_SEND_FILE_RESULT
	ERR_RECV_FILE
	ERR_RECV_FILE_DATA
)

func (c Code) String() string {
	switch c {
	case ERR_UNKNOWN:
		return "unknown error"
	case OK:
		return "ok"
	case ERR_NO_CLIENT:
		return "client instance missing"
	case ERR_SEND_TEXT:
		return "error starting text send"
	case ERR_SEND_TEXT_RESULT:
		return "error during text send"
	case ERR_RECV_TEXT:
		return "error during text receive"
	case ERR_RECV_TEXT_DATA:
		return "error during text receive reading data"
	case ERR_SEND_FILE:
		return "error starting file send"
	case ERR_SEND_FILE_RESULT:
		return "error during file send"
	case ERR_RECV_FILE:
		return "error during file receive"
	case ERR_RECV_FILE_DATA:
		return "error during file receive reading data"
	}
	return "unknown error"
}
