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
}

func (zp *ZeekProcess) String() string {
	return fmt.Sprintf("ZeekProcess{Pid=%d, Exe=%s, LoadAddr=0x%x, CallStackAddr=0x%x, FrameStackAddr=0x%x}",
		zp.Pid, zp.Exe, zp.LoadAddr, zp.CallStackAddr, zp.FrameStackAddr)
}

type SpyResult struct {
	Stack []Call
}

const (
	BRO_FUNC = iota
	BUILTIN_FUNC
)

// This is one entry of the stack
//
// Filename and Line are only filled if
type Call struct {
	Func     Func
	Filename string // from CallInfo->call->location->filename of next entry
	Line     int
}

type Func struct {
	Addr     uintptr
	Name     string
	Kind     int
	Filename string // Func->location->filename
	Line     int
}

var (
	emptyCallStack = []Call{Call{Func{0, "<empty_call_stack>", 1, "<zeek>", 0}, "<zeek>", 0}}
)

// Read all CallInfo entries stored in the call_stack vector.
//
// This assumes we have attached to the process, waited for it to stop
// and that it is safe to call PtracePeekData.
//
// XXX: This is *very* GCC (8.3.0), Zeek (3.0.1) and arch (x86_64) specific!
//      If we'd move the constants into a struct'ish thing, we migth be
//      a bit more generic.
func (zp *ZeekProcess) readCallStack() ([]Call, error) {

	vecStart, vecFinish, vecData, err := zp.readStdVector(zp.CallStackAddr)
	if err != nil {
		return nil, err
	}

	callStackSize := int(vecFinish-vecStart) / 24

	if callStackSize == 0 {
		return emptyCallStack, nil
	}

	result := make([]Call, callStackSize)

	funcBytes := 96
	funcData := make([]byte, funcBytes)

	// Iterate over all CallInfo entries
	for i := 0; i < callStackSize; i++ {
		offset := i * 24 // CallInfo is 3 pointers, 24 bytes

		// log.Printf("data[%d]: %#x", i, data[offset:offset+24])
		callPtr := uintptr(binary.LittleEndian.Uint64(vecData[offset : offset+8]))

		// If there is a callPtr, update the previous Call instance
		// to include the location information from it.
		if callPtr > 0 && i > 0 {
			filename, line, err := zp.readLocationFromBroObj(callPtr)
			if err != nil {
				return nil, err
			}
			result[i-1].Filename = filename
			result[i-1].Line = line
		}

		funcPtr := binary.LittleEndian.Uint64(vecData[offset+8 : offset+16])

		_, err = syscall.PtracePeekData(zp.Pid, uintptr(funcPtr), funcData)
		if err != nil {
			if err == nil {
				err = errors.New("peeking funcPtr failed")
			}
			return nil, err
		}

		kindValue := binary.LittleEndian.Uint64(funcData[56:64])
		cStrPointer := binary.LittleEndian.Uint64(funcData[72:80])

		funcName, err := zp.readNullTerminatedStr(uintptr(cStrPointer))
		if err != nil {
			return nil, err
		}
		kind := BRO_FUNC
		if kindValue > 0 {
			kind = BUILTIN_FUNC
		}

		locPtr := uintptr(binary.LittleEndian.Uint64(funcData[8:16]))
		filename, line, err := zp.readLocation(locPtr)
		if err != nil {
			return nil, err
		}

		f := Func{uintptr(funcPtr), funcName, kind, filename, line}
		result[i] = Call{f, "", 0}
		// log.Printf("result[%d]=%+v (funcPtr=%#x)\n", i, result[i], funcPtr)

	}

	// If the call_stack was of length 1, consult the g_frame_stack
	// to find the location of the next_stmt in the first frame there.
	//
	// The Func object inside CallInfo points to a `.bif` function,
	// and not the actul event handler that is running.
	//
	// This is a bit of a hack and it would be much nicer if we had
	// this information available elsewhere.
	if callStackSize == 1 {
		frameVecStart, frameVecFinish, frameVecData, err := zp.readStdVector(zp.FrameStackAddr)
		if err != nil {
			return nil, err
		}
		frameStackSize := (frameVecFinish - frameVecStart) / 8
		if frameStackSize < 1 {
			return nil, fmt.Errorf("Bad frameStackSize: %d", frameStackSize)
		}

		framePtr := uintptr(binary.LittleEndian.Uint64(frameVecData[:8]))
		// fmt.Printf("frameStackSize=%d framePtr=0x%x\n", frameStackSize, framePtr)

		// Read the next_stmt pointer and interpret it. It is at offset 144.
		stmtData := make([]byte, 8)
		_, err = syscall.PtracePeekData(zp.Pid, framePtr+144, stmtData)
		if err != nil {
			return nil, err
		}
		stmtPtr := uintptr(binary.LittleEndian.Uint64(stmtData[:8]))

		if stmtPtr > 0 {
			filename, line, err := zp.readLocationFromBroObj(stmtPtr)
			if err != nil {
				return nil, err
			}
			result[0].Filename = filename
			result[0].Line = line
		}
		// XXX: It would be nice if we could actually get the proper
		//      location of the event handler.
	}

	// XXX: If function at call_stack[0] is at a different location
	//      then what was found in the `call`, prepend the name/filename/line
	//      as a separate Call.
	//
	//      This adds a call from a .bif file to the stack.
	f0 := result[0].Func
	if f0.Filename != result[0].Filename && f0.Line != result[0].Line {
		result = append([]Call{Call{f0, f0.Filename, f0.Line}}, result...)
	}

	return result, nil
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

// A BroObj has its location pointer at offset 8, behind the vtable.
func (zp *ZeekProcess) readLocationFromBroObj(addr uintptr) (filename string, line int, err error) {
	data := make([]byte, 16) // vtable(8), locPtr(8)
	_, err = syscall.PtracePeekData(zp.Pid, uintptr(addr), data)
	if err != nil {
		return "", 0, err
	}
	locPtr := binary.LittleEndian.Uint64(data[8:16])
	filename, line, err = zp.readLocation(uintptr(locPtr))
	return

}

// addr must be a pointer to Location
// Memory layout of Location:
//   vtable(8)
//   filename(8)
//   first_line(4)
//   last_line(4)
func (zp *ZeekProcess) readLocation(addr uintptr) (filename string, line int, err error) {
	if addr == 0 {
		return
	}

	locData := make([]byte, 24)
	_, err = syscall.PtracePeekData(zp.Pid, addr, locData)
	if err != nil {
		return
	}
	cStrPtr := uintptr(binary.LittleEndian.Uint64(locData[8:16]))
	if cStrPtr == 0 {
		return
	}
	filename, err = zp.readNullTerminatedStr(cStrPtr)
	if err != nil {
		return
	}
	filename = filepath.Clean(filename)
	line = int(int32(binary.LittleEndian.Uint32(locData[16:20])))
	return
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

func (zp *ZeekProcess) Spy() (*SpyResult, error) {

	if err := zp.attach(); err != nil {
		log.Printf("ptrace attach failed for %d: %v\n", zp.Pid, err)
		return nil, err
	}
	defer zp.detach()

	if err := zp.wait(); err != nil {
		fmt.Printf("wait failed for %d: %v!\n", zp.Pid, err)
		return nil, err
	}

	stack, err := zp.readCallStack()
	if err != nil {
		return nil, err
	}

	return &SpyResult{stack}, nil
}

// Parses /proc/{pid} data and uses elf to find the call_stack address.
func ZeekProcessFromPid(pid int) *ZeekProcess {
	var f *elf.File
	var err error
	var exe string
	var symbols []elf.Symbol
	var callStackSym, frameStackSym elf.Symbol

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
		}

		if callStackSym.Value != 0 && frameStackSym.Value != 0 {
			break
		}
	}
	if callStackSym.Value == 0 {
		log.Fatalf("Could not find call_stack symbol in %s", exe)
	}
	if frameStackSym.Value == 0 {
		log.Fatalf("Could not find g_frame_stack symbol in %s", exe)
	}

	frameStackAddr := loadAddr + uintptr(frameStackSym.Value)
	callStackAddr := loadAddr + uintptr(callStackSym.Value)
	zp := ZeekProcess{pid, exe, loadAddr, callStackAddr, frameStackAddr}
	return &zp
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
