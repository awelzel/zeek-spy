// Given a stack, build up tables to be flushed out to the protobuf
package main

import (
	"compress/gzip"
	"io"
	"log"
	"time"

	"github.com/golang/protobuf/proto"
	"pprof_profile" // This looks like a hack
)

type profileBuilder struct {
	nanos      int64
	period     time.Duration
	strings    []string
	stringsMap map[string]int64
	samples    [][]uint64

	locationsMap map[LocationKey]uint64
	functionsMap map[FunctionKey]uint64
}

type FunctionKey struct {
	FilenameId, NameId, Line int64
}

type LocationKey struct {
	FuncId uint64
	Line   int
}

func NewProfileBuilder(period time.Duration) *profileBuilder {
	b := profileBuilder{}
	b.nanos = time.Now().UnixNano()
	b.period = period
	b.stringsMap = make(map[string]int64)
	for i, s := range []string{"", "samples", "count", "cpu", "nanoseconds"} {
		b.strings = append(b.strings, s)
		b.stringsMap[s] = int64(i)
	}

	b.functionsMap = make(map[FunctionKey]uint64)
	b.locationsMap = make(map[LocationKey]uint64)
	return &b
}

// Return the index of s in the string table
func (b *profileBuilder) GetStringIndex(s string) int64 {
	if i, ok := b.stringsMap[s]; ok {
		return i
	}
	i := int64(len(b.strings))
	b.strings = append(b.strings, s)
	b.stringsMap[s] = i
	return i
}

func (b *profileBuilder) GetFunctionId(filename, name string, line int64) uint64 {
	key := FunctionKey{b.GetStringIndex(filename), b.GetStringIndex(name), line}

	if i, ok := b.functionsMap[key]; ok {
		return i
	}
	i := uint64(len(b.functionsMap)) + 1 // id is required to be non-zero
	b.functionsMap[key] = i
	return i

}

func (b *profileBuilder) GetLocationId(funcId uint64, line int) uint64 {

	key := LocationKey{funcId, line}
	if i, ok := b.locationsMap[key]; ok {
		return i
	}
	i := uint64(len(b.locationsMap)) + 1 // id is required to be non-zero
	b.locationsMap[key] = i
	return i
}

func (b *profileBuilder) AddSample(stack []Call) {
	locations := make([]uint64, len(stack))
	for i, c := range stack {
		fn := c.Filename
		line := c.Line
		if fn == "" {
			fn = c.Func.Filename
			line = c.Func.Line
		}
		funcId := b.GetFunctionId(fn, c.Func.Name, int64(line))

		locId := b.GetLocationId(funcId, line)
		locations[i] = locId
	}
	b.samples = append(b.samples, locations)
}

func (b *profileBuilder) WriteProfile(w io.Writer) ([]byte, error) {

	samplesValueType := pprof_profile.ValueType{
		Type: b.GetStringIndex("samples"),
		Unit: b.GetStringIndex("count"),
	}
	cpuValueType := pprof_profile.ValueType{
		Type: b.GetStringIndex("cpu"),
		Unit: b.GetStringIndex("nanoseconds"),
	}

	samples := make([]*pprof_profile.Sample, len(b.samples))
	for i, locationIds := range b.samples {

		// Reverse locations (https://github.com/golang/go/wiki/SliceTricks#reversing)
		for j := len(locationIds)/2 - 1; j >= 0; j-- {
			opp := len(locationIds) - 1 - j
			locationIds[j], locationIds[opp] = locationIds[opp], locationIds[j]
		}

		samples[i] = new(pprof_profile.Sample)
		samples[i].LocationId = locationIds
		samples[i].Value = []int64{1, int64(b.period)}
	}

	functions := make([]*pprof_profile.Function, len(b.functionsMap))
	i := 0
	for funcKey, funcId := range b.functionsMap {
		functions[i] = new(pprof_profile.Function)
		functions[i].Id = funcId
		functions[i].Name = funcKey.NameId
		functions[i].Filename = funcKey.FilenameId
		i++
	}

	locations := make([]*pprof_profile.Location, len(b.locationsMap))

	i = 0
	for locKey, locId := range b.locationsMap {
		locations[i] = new(pprof_profile.Location)
		locations[i].Id = locId
		locations[i].Line = make([]*pprof_profile.Line, 1)
		locations[i].Line[0] = new(pprof_profile.Line)
		locations[i].Line[0].FunctionId = locKey.FuncId
		locations[i].Line[0].Line = int64(locKey.Line)
		i++
	}

	p := pprof_profile.Profile{
		SampleType:        []*pprof_profile.ValueType{&samplesValueType, &cpuValueType},
		Sample:            samples,
		Function:          functions,
		Location:          locations,
		StringTable:       b.strings,
		TimeNanos:         b.nanos,
		DurationNanos:     time.Now().UnixNano() - b.nanos,
		Period:            b.period.Nanoseconds(),
		PeriodType:        &cpuValueType,
		DefaultSampleType: b.GetStringIndex("samples"),
	}
	data, err := proto.Marshal(&p)
	if err != nil {
		log.Fatalf("Failed marshaling: %v", err)
	}

	zw := gzip.NewWriter(w)
	defer zw.Close()
	zw.Write(data)

	return data, nil
}
