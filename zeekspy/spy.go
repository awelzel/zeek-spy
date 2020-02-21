// Spying on a zeek process
//
// TODO: make some effort to abstract GCC specifics (?)
//
package zeekspy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"debug/elf"
)

type ZeekProcess struct {
	Pid            int
	Exe            string
	LoadAddr       uintptr
	CallStackAddr  uintptr
	FrameStackAddr uintptr
	VersionAddr    uintptr
}

func (zp *ZeekProcess) String() string {
	return fmt.Sprintf("ZeekProcess{Pid=%d, Exe=%s, LoadAddr=%#x, CallStackAddr=%#x, FrameStackAddr=%#x VersionAddr=%#x}",
		zp.Pid, zp.Exe, zp.LoadAddr, zp.CallStackAddr, zp.FrameStackAddr, zp.VersionAddr)
}

type SpyResult struct {
	Stack []Call
	Empty bool
}

const (
	BRO_FUNC = iota
	BUILTIN_FUNC
)

// This is one entry of the stack
type Call struct {
	Func     *Func
	Filename string
	Line     int
}

type Location struct {
	Filename string
	Start    int
	End      int
}

type Func struct {
	Addr uintptr
	Name string
	Kind int
	Loc  Location
}

func (f *Func) String() string {
	return fmt.Sprintf("Func{%s %s:%d-%d}", f.Name, f.Loc.Filename, f.Loc.Start, f.Loc.End)
}

var (
	emptyCallStack = []Call{Call{&Func{0, "<empty_call_stack>", 1, Location{"<zeek>", 0, 0}}, "<zeek>", 0}}
	nullLocation   = Location{"", 0, 0}
)

// Read all CallInfo entries stored in the call_stack vector.
//
// This assumes we have attached to the process, waited for it to stop
// and that it is safe to call PtracePeekData.
//
// XXX: This is *very* GCC (8.3.0), Zeek (3.0.1) and arch (x86_64) specific!
//      If we'd move the constants into a struct'ish thing, we migth be
//      a bit more generic.
//
// XXX: If the interplay of of call_stack / g_frame_stack ever changes this
//      will break left and right.
func (zp *ZeekProcess) readCallStack() ([]Call, bool, error) {

	vecStart, vecFinish, vecData, err := zp.readStdVector(zp.CallStackAddr)
	if err != nil {
		return nil, false, err
	}

	callStackSize := int(vecFinish-vecStart) / 24
	if callStackSize == 0 {
		return emptyCallStack, true, nil
	}

	result := make([]Call, callStackSize)

	for i := 0; i < callStackSize; i++ {
		offset := i * 24 // CallInfo is 3 pointers, 24 bytes

		// log.Printf("data[%d]: %#x", i, data[offset:offset+24])
		callPtr := uintptr(binary.LittleEndian.Uint64(vecData[offset : offset+8]))

		// If there is a callPtr, update the previous Call instance
		// to include the location information from it.
		if callPtr > 0 && i > 0 {
			loc, err := zp.readLocationFromBroObj(callPtr)
			if err != nil {
				return nil, false, err
			}
			result[i-1].Filename = loc.Filename
			result[i-1].Line = loc.Start
		}

		funcPtr := uintptr(binary.LittleEndian.Uint64(vecData[offset+8 : offset+16]))
		funcObj, err := zp.readFuncObject(funcPtr)
		if err != nil {
			return nil, false, err
		}
		result[i] = Call{funcObj, "", 0}
	}

	// Find the approximate location of the current running code
	// via the top most g_frame_stack Frame->next_stmt, but only
	// if g_frame_stack and call_stack have the same size.
	frameVecStart, frameVecFinish, frameVecData, err := zp.readStdVector(zp.FrameStackAddr)
	if err != nil {
		return nil, false, err
	}
	frameStackSize := int((frameVecFinish - frameVecStart) / 8)
	if frameStackSize >= callStackSize {

		// Use the "right" frame if len(g_frame_stack) > len(call_stack)
		framePtrOffset := len(frameVecData) - (frameStackSize-callStackSize+1)*8
		framePtr := uintptr(binary.LittleEndian.Uint64(frameVecData[framePtrOffset : framePtrOffset+8]))

		// Read the next_stmt pointer of the Frame and interpret it.
		// It is at offset 144.
		stmtData := make([]byte, 8)
		_, err = syscall.PtracePeekData(zp.Pid, framePtr+144, stmtData)
		if err != nil {
			return nil, false, err
		}
		stmtPtr := uintptr(binary.LittleEndian.Uint64(stmtData[:8]))

		if stmtPtr > 0 {
			loc, err := zp.readLocationFromBroObj(stmtPtr)
			if err != nil {
				return nil, false, err
			}
			result[callStackSize-1].Filename = loc.Filename
			result[callStackSize-1].Line = loc.Start
		}
	} else if callStackSize > frameStackSize {
		f := result[callStackSize-1].Func
		if f.Kind != BUILTIN_FUNC {
			log.Printf("[WARN] call_stack larger, non built-in: %+v\n", f)
		}
	}

	//
	// XXX: If the function at call_stack[0] is in a different file
	//      than what was found via `call` or `Frame->next_stmt`, prepend
	//      the original name/filename/line as a separate Call and "rewrite"
	//      the original function to be more in line what the location
	//      reported...
	//
	//      This is a limitations, as there's a single BroObj capturing
	//      each event handler.
	//
	f0 := result[0].Func
	if f0.Loc.Filename != result[0].Filename {

		fakeFunc := *f0

		// Update entry to at least point to the right filename
		f0.Loc.Filename = result[0].Filename
		f0.Loc.Start = 0 // We just don't know :-(
		f0.Loc.End = 0

		fakeCall := Call{&fakeFunc, fakeFunc.Loc.Filename, fakeFunc.Loc.Start}
		result = append([]Call{fakeCall}, result...)
	}

	// for i, entry := range result {
	//	log.Printf("result[%d]=%s:%d %+v\n", i, entry.Filename, entry.Line, entry.Func)
	// }

	return result, false, nil
}

func (zp *ZeekProcess) readStdVector(addr uintptr) (uintptr, uintptr, []byte, error) {
	data := make([]byte, 16)
	_, err := syscall.PtracePeekData(zp.Pid, addr, data)
	if err != nil {
		return 0, 0, nil, err
	}
	start := uintptr(binary.LittleEndian.Uint64(data[:8]))
	finish := uintptr(binary.LittleEndian.Uint64(data[8:16]))

	data = make([]byte, finish-start)
	count, err := syscall.PtracePeekData(zp.Pid, start, data)
	if err != nil {
		return 0, 0, nil, err
	}
	if count != int(finish-start) {
		return 0, 0, nil, fmt.Errorf("Bad count %d", count)
	}

	return start, finish, data, nil
}

// Given a pointer to a Func object, extract name and location information.
func (zp *ZeekProcess) readFuncObject(addr uintptr) (*Func, error) {

	funcData := make([]byte, 96)
	_, err := syscall.PtracePeekData(zp.Pid, addr, funcData)
	if err != nil {
		return nil, err
	}
	kindValue := binary.LittleEndian.Uint64(funcData[56:64])
	kind := BRO_FUNC
	if kindValue > 0 {
		kind = BUILTIN_FUNC
	}

	// std:string at offset 72
	cStrPointer := uintptr(binary.LittleEndian.Uint64(funcData[72:80]))

	funcName, err := zp.readNullTerminatedStr(cStrPointer)
	if err != nil {
		return nil, err
	}

	locPtr := uintptr(binary.LittleEndian.Uint64(funcData[8:16]))
	loc, err := zp.readLocation(locPtr)
	if err != nil {
		return nil, err
	}
	return &Func{addr, funcName, kind, *loc}, nil
}

// A BroObj has its location pointer at offset 8, behind the vtable.
func (zp *ZeekProcess) readLocationFromBroObj(addr uintptr) (*Location, error) {
	data := make([]byte, 16) // vtable(8), locPtr(8)
	_, err := syscall.PtracePeekData(zp.Pid, uintptr(addr), data)
	if err != nil {
		return nil, err
	}
	locPtr := uintptr(binary.LittleEndian.Uint64(data[8:16]))
	return zp.readLocation(locPtr)

}

// addr must be a pointer to Location
// Memory layout of Location:
//   vtable(8)
//   filename(8)
//   first_line(4)
//   last_line(4)
func (zp *ZeekProcess) readLocation(addr uintptr) (*Location, error) {
	if addr == 0 {
		return &nullLocation, nil
	}

	locData := make([]byte, 24)
	_, err := syscall.PtracePeekData(zp.Pid, addr, locData)
	if err != nil {
		return nil, err
	}
	cStrPtr := uintptr(binary.LittleEndian.Uint64(locData[8:16]))
	if cStrPtr == 0 {
		return &nullLocation, nil
	}
	filename, err := zp.readNullTerminatedStr(cStrPtr)
	if err != nil {
		return nil, err
	}
	filename = filepath.Clean(filename)
	start := int(int32(binary.LittleEndian.Uint32(locData[16:20])))
	end := int(int32(binary.LittleEndian.Uint32(locData[20:24])))
	return &Location{filename, start, end}, nil
}

func (zp *ZeekProcess) readNullTerminatedStr(addr uintptr) (result string, err error) {
	size := 8
	data := make([]byte, size)
	var buffer bytes.Buffer
	for {
		_, err := syscall.PtracePeekData(zp.Pid, addr, data)
		if err != nil {
			return "", err
		}

		for _, b := range data {
			if b == 0 {
				goto done
			}
			buffer.WriteByte(b)
		}
		addr += uintptr(size)
	}
done:
	return buffer.String(), nil
}

func (zp *ZeekProcess) attach() (err error) {
	return syscall.PtraceAttach(zp.Pid)
}

func (zp *ZeekProcess) wait() (err error) {
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(zp.Pid, &status, 0, nil); err != nil {
		return err
	}
	if status.Exited() {
		return errors.New("process exited")
	}
	if !status.Stopped() {
		return errors.New("process did not stop")
	}
	return err
}

func (zp *ZeekProcess) detach() {
	if err := syscall.PtraceDetach(zp.Pid); err != nil {
		log.Printf("[WARN] Could not detach from process: %v\n", err)
	}
}

// Read the version from the process
func (zp *ZeekProcess) Version() (string, error) {
	if err := zp.attach(); err != nil {
		return "", err
	}
	defer zp.detach()

	if err := zp.wait(); err != nil {
		log.Printf("[WARN] wait() failed for %d: %v!\n", zp.Pid, err)
		return "", err
	}

	return zp.readNullTerminatedStr(zp.VersionAddr)
}

func (zp *ZeekProcess) Spy() (*SpyResult, error) {

	if err := zp.attach(); err != nil {
		return nil, err
	}
	defer zp.detach()

	if err := zp.wait(); err != nil {
		log.Printf("[WARN] wait() failed for %d: %v!\n", zp.Pid, err)
		return nil, err
	}

	stack, empty, err := zp.readCallStack()
	if err != nil {
		return nil, err
	}

	return &SpyResult{stack, empty}, nil
}

// Parses /proc/{pid} data and uses elf to find the call_stack address.
func ZeekProcessFromPid(pid int) *ZeekProcess {
	var f *elf.File
	var err error
	var exe string
	var symbols []elf.Symbol
	var callStackSym, frameStackSym, versionSym elf.Symbol

	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	if exe, err = os.Readlink(exeLink); err != nil {
		log.Fatalf("Could not readlink %v: %v", exeLink, err)
	}

	if f, err = elf.Open(exe); err != nil {
		log.Fatalf("Could not open %v: %v", exe, err)
	}

	defer f.Close()

	loadAddr, err := findLoadAddr(pid, exe)

	if symbols, err = f.DynamicSymbols(); err != nil {
		log.Fatalf("Could not fetch symbols from %v: %v", f, err)
	}
	for _, symbol := range symbols {
		if symbol.Name == "call_stack" {
			callStackSym = symbol
		} else if symbol.Name == "g_frame_stack" {
			frameStackSym = symbol
		} else if symbol.Name == "version" {
			versionSym = symbol
		}

		if callStackSym.Value != 0 && frameStackSym.Value != 0 && versionSym.Value != 0 {
			break
		}
	}
	if callStackSym.Value == 0 {
		log.Fatalf("Could not find call_stack symbol in %s", exe)
	}
	if frameStackSym.Value == 0 {
		log.Fatalf("Could not find g_frame_stack symbol in %s", exe)
	}
	if versionSym.Value == 0 {
		log.Fatalf("Could not find version symbol in %s", exe)
	}

	frameStackAddr := loadAddr + uintptr(frameStackSym.Value)
	callStackAddr := loadAddr + uintptr(callStackSym.Value)
	versionAddr := loadAddr + uintptr(versionSym.Value)
	return &ZeekProcess{
		Pid:            pid,
		Exe:            exe,
		LoadAddr:       loadAddr,
		CallStackAddr:  callStackAddr,
		FrameStackAddr: frameStackAddr,
		VersionAddr:    versionAddr}
}

// Parse /proc/<pid>/maps and return the lowest address for exeFilename
func findLoadAddr(pid int, exeFilename string) (uintptr, error) {
	var resultAddr uint64 = math.MaxUint64

	maps := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(maps)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, exeFilename) {
			continue
		}
		fields := strings.Split(line, "-")
		if addr, err := strconv.ParseUint(fields[0], 16, 64); err == nil {
			// fmt.Printf("%s: %s 0:%v\n", maps, line, addr)
			if addr < resultAddr {
				resultAddr = addr
			}
		}
	}
	return uintptr(resultAddr), nil
}
