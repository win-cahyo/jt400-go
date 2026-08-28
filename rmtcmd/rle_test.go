package rmtcmd

import (
	"bytes"
	"testing"
)

func TestDecompressRLE(t *testing.T) {
	tests := []struct {
		name    string
		source  []byte
		declLen int
		want    []byte
		wantErr bool
	}{
		{
			name:    "no RLE records, literal bytes only",
			source:  []byte("HELLO"),
			declLen: 5,
			want:    []byte("HELLO"),
		},
		{
			name:    "escaped literal escape byte",
			source:  []byte{rleEscape, rleEscape},
			declLen: 1,
			want:    []byte{rleEscape},
		},
		{
			name:    "repeater record expands a byte pair",
			source:  []byte{rleEscape, 0x40, 0x40, 0x00, 0x03},
			declLen: 6,
			want:    bytes.Repeat([]byte{0x40, 0x40}, 3),
		},
		{
			name: "literal, repeater, and escaped-escape mixed",
			source: append(append(append([]byte("AB"),
				rleEscape, 0x40, 0x40, 0x00, 0x02),
				'C'),
				rleEscape, rleEscape),
			declLen: 8,
			want:    append(append(append([]byte("AB"), 0x40, 0x40, 0x40, 0x40), 'C'), rleEscape),
		},
		{
			name:    "truncated escape record at end of data",
			source:  []byte{rleEscape},
			wantErr: true,
		},
		{
			name:    "truncated repeater record at end of data",
			source:  []byte{rleEscape, 0x40, 0x40, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decompressRLE(tt.source, tt.declLen)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("decompressRLE(%v) = %v, %v; want an error", tt.source, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("decompressRLE(%v) unexpected error: %v", tt.source, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("decompressRLE(%v) = %v; want %v", tt.source, got, tt.want)
			}
		})
	}
}
