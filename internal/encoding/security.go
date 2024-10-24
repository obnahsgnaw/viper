package encoding

import (
	"errors"
	"github.com/obnahsgnaw/application/pkg/security"
	"strings"
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
		b, iv, err = s.es.Encrypt(b, s.key, true)
		if err == nil {
			b = []byte(string(b) + "@" + string(iv))
		}
	}
	return b, err
}

func (s *Security) Decode(decoder Decoder, b []byte, v map[string]interface{}) error {
	if s.key != nil {
		var iv []byte
		var err error
		bs := strings.Split(string(b), "@")
		if len(bs) != 2 {
			return errors.New("security codec: invalid format")
		}
		b, iv = []byte(bs[0]), []byte(bs[1])
		b, err = s.es.Decrypt(b, s.key, iv, true)
		if err != nil {
			return err
		}
	}
	return decoder.Decode(b, v)
}
