package dataplane

import "testing"

func TestReaderQuiescenceRequiresEveryCPU(t *testing.T) {
	for _, test := range []struct {
		name     string
		active   []uint64
		expected bool
	}{
		{"missing observation", nil, false},
		{"one idle CPU", []uint64{0}, true},
		{"all idle CPUs", []uint64{0, 0, 0, 0}, true},
		{"first reader active", []uint64{1, 0, 0}, false},
		{"last reader active", []uint64{0, 0, 2}, false},
		{"invalid underflow remains busy", []uint64{^uint64(0)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := readersQuiescent(test.active); got != test.expected {
				t.Fatalf("quiescent = %v, want %v", got, test.expected)
			}
		})
	}
}
