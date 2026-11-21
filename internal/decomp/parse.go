package decomp

import (
	"encoding/binary"
	"fmt"
)

// parse reads the BMB1 header, fragment table and block index.
// Block payloads are not copied; the returned blocks point into data.
func parse(data []byte, q Quota) (map[uint32][]byte, []block, error) {
	if len(data) < 8 {
		return nil, nil, newError("parse", fmt.Sprintf("truncated header: %d bytes", len(data)))
	}
	if string(data[:4]) != string(Magic) {
		return nil, nil, newError("parse", "bad magic")
	}
	fragCount := int(binary.LittleEndian.Uint16(data[4:6]))
	blockCount := int(binary.LittleEndian.Uint16(data[6:8]))
	if q.MaxFragments > 0 && fragCount > q.MaxFragments {
		return nil, nil, newError("parse", fmt.Sprintf("fragment count %d exceeds quota %d", fragCount, q.MaxFragments))
	}
	if q.MaxBlocks > 0 && blockCount > q.MaxBlocks {
		return nil, nil, newError("parse", fmt.Sprintf("block count %d exceeds quota %d", blockCount, q.MaxBlocks))
	}

	off := 8
	frags := make(map[uint32][]byte, fragCount)
	for i := 0; i < fragCount; i++ {
		if off+8 > len(data) {
			return nil, nil, newError("parse", fmt.Sprintf("truncated fragment table at entry %d", i))
		}
		id := binary.LittleEndian.Uint32(data[off:])
		n := int(binary.LittleEndian.Uint32(data[off+4:]))
		off += 8
		if n < 0 || off+n > len(data) {
			return nil, nil, newError("parse", fmt.Sprintf("fragment %d length %d overruns input", id, n))
		}
		frags[id] = data[off : off+n]
		off += n
	}

	blocks := make([]block, 0, blockCount)
	for i := 0; i < blockCount; i++ {
		if off+13 > len(data) {
			return nil, nil, newError("parse", fmt.Sprintf("truncated block index at entry %d", i))
		}
		b := block{
			codec:  data[off],
			fragID: binary.LittleEndian.Uint32(data[off+1:]),
			clen:   binary.LittleEndian.Uint32(data[off+5:]),
			ulen:   binary.LittleEndian.Uint32(data[off+9:]),
		}
		off += 13
		if int64(b.clen) > int64(len(data)-off) {
			return nil, nil, newError("parse", fmt.Sprintf("block %d payload %d overruns input", i, b.clen))
		}
		b.off = off
		off += int(b.clen)
		blocks = append(blocks, b)
	}
	return frags, blocks, nil
}
