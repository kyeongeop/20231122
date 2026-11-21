package decomp

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
)

// Fragment is a named dictionary fragment to embed in a container.
type Fragment struct {
	ID   uint32
	Data []byte
}

// BlockSpec describes one block to encode with Build.
type BlockSpec struct {
	Codec byte // 0 = store, 1 = flate
	Frag  uint32
	Raw   []byte // uncompressed payload; Build compresses when Codec == 1
}

// Build encodes fragments and blocks into a BMB1 container. It is used by
// the scenario generator and the seed corpus builder.
func Build(frags []Fragment, blocks []BlockSpec) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	buf.Write(Magic)
	if err := binary.Write(buf, binary.LittleEndian, uint16(len(frags))); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint16(len(blocks))); err != nil {
		return nil, err
	}
	for _, f := range frags {
		if err := binary.Write(buf, binary.LittleEndian, f.ID); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(f.Data))); err != nil {
			return nil, err
		}
		buf.Write(f.Data)
	}
	for _, b := range blocks {
		payload := b.Raw
		if b.Codec == 1 {
			var cbuf bytes.Buffer
			var w *flate.Writer
			var err error
			frag := findFrag(frags, b.Frag)
			if frag != nil {
				w, err = flate.NewWriterDict(&cbuf, flate.BestCompression, frag)
			} else {
				w, err = flate.NewWriter(&cbuf, flate.BestCompression)
			}
			if err != nil {
				return nil, err
			}
			if _, err := w.Write(b.Raw); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			payload = cbuf.Bytes()
		}
		buf.WriteByte(b.Codec)
		if err := binary.Write(buf, binary.LittleEndian, b.Frag); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(payload))); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(b.Raw))); err != nil {
			return nil, err
		}
		buf.Write(payload)
	}
	return buf.Bytes(), nil
}

func findFrag(frags []Fragment, id uint32) []byte {
	for _, f := range frags {
		if f.ID == id {
			return f.Data
		}
	}
	return nil
}
