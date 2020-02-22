package zeekspy

import (
	"testing"
)

func TestNoEntry(t *testing.T) {
	got, ok := getStructOffsets("1.0")
	if got != nil || ok {
		t.Errorf("Expected nil, got %v", got)
	}
}

func TestVersions(t *testing.T) {

	var table = map[string]string{
		"3.0.2":     "3.0",
		"3.1.0":     "3.1",
		"3.1.0-rc1": "3.1",
	}

	for k, v := range table {
		t.Run(k, func(t *testing.T) {
			offsets, ok := getStructOffsets(k)
			if !ok {
				t.Errorf("OK is false?\n")
			}
			if offsets != structOffsetsMap[v] {
				t.Errorf("Expected %v entry, got %v", v, offsets)
			}
		})
	}
}
