package zeekspy

import (
	"testing"
	"time"
)

func TestAddSample(t *testing.T) {

	b := NewProfileBuilder(time.Duration(1))
	f := Func{123, "dns_message", 0, Location{"dns.bif", 442, 450}}
	c := Call{&f, "test/data.zeek", 42}
	stack := []Call{c}

	b.AddSample(stack)

	/* data, _ := b.MakeProto()
	fmt.Printf("data: \n\n(%x)\n\n", data) */

}

func TestGetStringIndex(t *testing.T) {
	b := NewProfileBuilder(time.Duration(1))

	t.Run("Empty string at 0", func(t *testing.T) {
		if i := b.GetStringIndex(""); i != 0 {
			t.Errorf("Expected i=0, got i=%d", i)
		}
	})
	t.Run("count at 2", func(t *testing.T) {
		if i := b.GetStringIndex("count"); i != 2 {
			t.Errorf("Expected i=2, got i=%d", i)
		}
	})
	t.Run("new string at 5", func(t *testing.T) {
		if i := b.GetStringIndex("dns_message"); i != 5 {
			t.Errorf("Expected i=5, got i=%d", i)
		}
		if i := b.GetStringIndex("dns_message"); i != 5 {
			t.Errorf("Expected i=5, got i=%d", i)
		}
	})
}
