package zeekspy

import (
	"strings"
)

type StructOffsets struct {
	LocationSize      int
	LocationFilename  int
	LocationFirstLine int
	LocationLastLine  int
}

var structOffsetsMap = map[string]*StructOffsets{
	"3.0": &StructOffsets{
		LocationSize:      24,
		LocationFilename:  8,
		LocationFirstLine: 16,
		LocationLastLine:  20,
	},
	"3.1": &StructOffsets{
		LocationSize:      16,
		LocationFilename:  0,
		LocationFirstLine: 8,
		LocationLastLine:  12,
	},
}

func getStructOffsets(version string) (*StructOffsets, bool) {
	match := 0
	use := ""
	for k := range structOffsetsMap {
		if !strings.HasPrefix(version, k) {
			continue
		}
		if m := len(version) - len(strings.TrimPrefix(version, k)); m > match {
			use = k
		}
	}
	if use == "" {
		return nil, false
	}
	return structOffsetsMap[use], true
}
