package wormhole

type transferOptions struct {
	code         string
	progressFunc progressFunc
}

type TransferOption interface {
	setOption(*transferOptions) error
}

type codeTransferOption struct {
	code string
}

func (o codeTransferOption) setOption(opts *transferOptions) error {
	if err := validateCode(o.code); err != nil {
		return err
	}

	opts.code = o.code
	return nil
}

// WithCode returns a TransferOption to use a specific nameplate+code
// instead of generating one dynamically.
func WithCode(code string) TransferOption {
	return codeTransferOption{code: code}
}

type progressFunc func(sentBytes int64, totalBytes int64)

type progressTransferOption struct {
	progressFunc progressFunc
}

func (o progressTransferOption) setOption(opts *transferOptions) error {
	opts.progressFunc = o.progressFunc
	return nil
}

// WithProgress returns a TransferOption to track the progress of the data
// transfer. It takes a callback function that will be called for each
// chunk of data successfully written.
//
// WithProgress is only minimally supported in SendText. SendText does
// not use the wormhole transit protocol so it is not able to detect
// the progress of the receiver. This limitation does not apply to
// SendFile or SendDirectory.
func WithProgress(f func(sentBytes int64, totalBytes int64)) TransferOption {
	return progressTransferOption{f}
}
