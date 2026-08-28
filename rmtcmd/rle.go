package rmtcmd

import "fmt"

// rleEscape is the escape byte JTOpen's DataStreamCompression always uses
// for as-rmtcmd RLE records (DataStreamCompression.DEFAULT_ESCAPE).
const rleEscape = 0x1B

// decompressRLE reverses the as-rmtcmd host server's RLE (run-length
// encoding) compression of a CallProgram output parameter (usage codes 22
// and 23 in the reply's parameter-usage field). Transcribed from JTOpen's
// DataStreamCompression.decompressRLEInternal, minus its overflow/realloc
// bookkeeping — since the reply always states the true decompressed length
// up front, the destination buffer is sized correctly from the start.
//
// Record format, scanning source left to right:
//   - escape, escape                   -> emit one literal escape byte
//   - escape, b1, b2, countHi, countLo -> emit the pair (b1, b2), count times
//   - any other byte                   -> copied through as-is
func decompressRLE(source []byte, decompressedLength int) ([]byte, error) {
	dest := make([]byte, 0, decompressedLength)
	i := 0
	for i < len(source) {
		if source[i] != rleEscape {
			dest = append(dest, source[i])
			i++
			continue
		}
		if i+1 >= len(source) {
			return nil, fmt.Errorf("rmtcmd: truncated RLE escape record at end of compressed data")
		}
		if source[i+1] == rleEscape {
			dest = append(dest, rleEscape)
			i += 2
			continue
		}
		if i+4 >= len(source) {
			return nil, fmt.Errorf("rmtcmd: truncated RLE repeater record at end of compressed data")
		}
		b1, b2 := source[i+1], source[i+2]
		count := int(source[i+3])<<8 | int(source[i+4])
		for k := 0; k < count; k++ {
			dest = append(dest, b1, b2)
		}
		i += 5
	}
	return dest, nil
}
