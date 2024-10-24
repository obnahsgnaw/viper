package encoding

import (
	"bytes"
	"errors"
	"github.com/obnahsgnaw/application/pkg/security"
)

type Security struct {
	es  *security.EsCrypto
	key []byte
}

func newSecurity() *Security {
	return &Security{es: security.NewEsCrypto(security.Aes128, security.CbcMode)}
}

func (s *Security) WithKey(key [16]byte) {
	s.key = key[:]
}

func (s *Security) WithoutKey() {
	s.key = nil
}

func (s *Security) Encode(encoder Encoder, v map[string]interface{}) ([]byte, error) {
	b, err := encoder.Encode(v)
	if err != nil {
		return nil, err
	}
	if s.key != nil {
		var iv []byte
		b, iv, err = s.es.Encrypt(b, s.key, false)
		if err == nil {
			b = bytes.Join([][]byte{b, iv}, []byte("@"))
		}
	}
	return b, err
}

func (s *Security) Decode(decoder Decoder, b []byte, v map[string]interface{}) error {
	if s.key != nil {
		var iv []byte
		var err error
		bs := bytes.Split(b, []byte("@"))
		if len(bs) != 2 {
			return errors.New("security codec: invalid format")
		}
		b, iv = bs[0], bs[1]
		b, err = s.es.Decrypt(b, s.key, iv, false)
		if err != nil {
			return err
		}
	}
	return decoder.Decode(b, v)
}
