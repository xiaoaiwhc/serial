// +build windows

package serial

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type Port struct {
	f  *os.File
	fd syscall.Handle
	rl sync.Mutex
	wl sync.Mutex
	ro *syscall.Overlapped
	wo *syscall.Overlapped
}

type structDCB struct {
	DCBlength, BaudRate                            uint32
	flags                                          [4]byte
	wReserved, XonLim, XoffLim                     uint16
	ByteSize, Parity, StopBits                     byte
	XonChar, XoffChar, ErrorChar, EofChar, EvtChar byte
	wReserved1                                     uint16
}

type structTimeouts struct {
	ReadIntervalTimeout         uint32
	ReadTotalTimeoutMultiplier  uint32
	ReadTotalTimeoutConstant    uint32
	WriteTotalTimeoutMultiplier uint32
	WriteTotalTimeoutConstant   uint32
}

type structCOMSTAT struct {
	//flags represents: fCtsHold, fDsrHold, fRlsdHold, fXoffHold, fXoffSent, fEof, fTxim
	flags		[7]byte		
	fReserved	[25]byte
	cbInQue		uint32
	cbOutQue	uint32
}

func openPort(name string, baud int, readTimeout time.Duration) (p *Port, err error) {
	if len(name) > 0 && name[0] != '\\' {
		name = "\\\\.\\" + name
	}

	h, err := syscall.CreateFile(syscall.StringToUTF16Ptr(name),
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OVERLAPPED,
		0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), name)
	defer func() {
		if err != nil {
			f.Close()
		}
	}()

	if err = setCommState(h, baud); err != nil {
		return
	}
	if err = setupComm(h, 2048, 2048); err != nil {
		return
	}
	if err = setCommTimeouts(h, readTimeout); err != nil {
		return
	}
	if err = setCommMask(h); err != nil {
		return
	}

	ro, err := newOverlapped()
	if err != nil {
		return
	}
	wo, err := newOverlapped()
	if err != nil {
		return
	}
	port := new(Port)
	port.f = f
	port.fd = h
	port.ro = ro
	port.wo = wo
	
	return port, nil
}

func (p *Port) Close() error {
	return p.f.Close()
}

func (p *Port) Write(buf []byte) (int, error) {
	p.wl.Lock()
	defer p.wl.Unlock()

	if err := resetEvent(p.wo.HEvent); err != nil {
		return 0, err
	}
	
	var dwErr uint
	var comstat structCOMSTAT
	clearCommError(p.fd, &dwErr, &comstat)
	
	var n uint32
	err := syscall.WriteFile(p.fd, buf, &n, p.wo)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return int(n), err
	}
	return getOverlappedResult(p.fd, p.wo)
}

func (p *Port) Read(buf []byte) (int, error) {
	if p == nil || p.f == nil {
		return 0, fmt.Errorf("Invalid port on read %v %v", p, p.f)
	}

	p.rl.Lock()
	defer p.rl.Unlock()

	
	if err := resetEvent(p.ro.HEvent); err != nil {
		return 0, err
	}
	
	var dwErr uint
	var comstat structCOMSTAT
	clearCommError(p.fd, &dwErr, &comstat)
	
	var done uint32
	err := syscall.ReadFile(p.fd, buf, &done, p.ro)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return int(done), err
	}
	return getOverlappedResult(p.fd, p.ro)
}

// Discards data written to the port but not transmitted,
// or data received but not read
func (p *Port) Flush() error {
	if err := purgeCommTx(p.fd); err != nil {
		return err
	}
	
	if err := purgeCommRx(p.fd); err != nil {
		return err
	}
	
	return nil
}

func (p *Port) FlushTx() error {
	return purgeCommTx(p.fd)
}

func (p *Port) FlushRx() error {
	return purgeCommRx(p.fd)
}

var (
	nSetCommState,
	nGetCommState,
	nSetCommTimeouts,
	nGetCommTimeouts,
	nSetCommMask,
	nSetupComm,
	nGetOverlappedResult,
	nCreateEvent,
	nResetEvent,
	nPurgeComm,
	nClearCommError,
	nFlushFileBuffers uintptr
)

func init() {
	k32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		panic("LoadLibrary " + err.Error())
	}
	defer syscall.FreeLibrary(k32)

	nSetCommState = getProcAddr(k32, "SetCommState")
	nGetCommState = getProcAddr(k32, "GetCommState")
	nSetCommTimeouts = getProcAddr(k32, "SetCommTimeouts")
	nGetCommTimeouts = getProcAddr(k32, "GetCommTimeouts")
	nSetCommMask = getProcAddr(k32, "SetCommMask")
	nSetupComm = getProcAddr(k32, "SetupComm")
	nGetOverlappedResult = getProcAddr(k32, "GetOverlappedResult")
	nCreateEvent = getProcAddr(k32, "CreateEventW")
	nResetEvent = getProcAddr(k32, "ResetEvent")
	nPurgeComm = getProcAddr(k32, "PurgeComm")
	nClearCommError = getProcAddr(k32, "ClearCommError")
	nFlushFileBuffers = getProcAddr(k32, "FlushFileBuffers")
}

func getProcAddr(lib syscall.Handle, name string) uintptr {
	addr, err := syscall.GetProcAddress(lib, name)
	if err != nil {
		panic(name + " " + err.Error())
	}
	return addr
}

func getCommState(h syscall.Handle, dcb *structDCB) error {
	r, _, err := syscall.Syscall(nGetCommState, 2, uintptr(h), uintptr(unsafe.Pointer(dcb)), 0)
	if r == 0 {
		return err 
	}
	
	return nil
}

func setCommState(h syscall.Handle, baud int) error {
	var params structDCB
	
	err := getCommState(h, &params)
	if err != nil {
		return err 
	}
	
	params.DCBlength = uint32(unsafe.Sizeof(params))

	params.flags[0] = 0x01  // fBinary
	params.flags[0] |= 0x10 // Assert DSR
	params.flags[2] |= 0x10 // RTS_CONTROL_ENABLE
	params.BaudRate = uint32(baud)
	params.ByteSize = 8

	r, _, err := syscall.Syscall(nSetCommState, 2, uintptr(h), uintptr(unsafe.Pointer(&params)), 0)
	if r == 0 {
		return err
	}
	return nil
}

func getCommTimeouts(h syscall.Handle, timeout *structTimeouts) error {
	r, _, err := syscall.Syscall(nGetCommTimeouts, 2, uintptr(h), uintptr(unsafe.Pointer(timeout)), 0)
	if r == 0 {
		return err
	}
	return nil	
}

func setCommTimeouts(h syscall.Handle, readTimeout time.Duration) error {
	const MAXDWORD = 1<<32 - 1

	// blocking read by default
	var timeoutMs int64 = MAXDWORD - 1

	if readTimeout > 0 {
		// non-blocking read
		timeoutMs = readTimeout.Nanoseconds() / 1e6
		if timeoutMs < 1 {
			timeoutMs = 1
		} else if timeoutMs > MAXDWORD-1 {
			timeoutMs = MAXDWORD - 1
		}
	}

	/* From http://msdn.microsoft.com/en-us/library/aa363190(v=VS.85).aspx

		 For blocking I/O see below:

		 Remarks:

		 If an application sets ReadIntervalTimeout and
		 ReadTotalTimeoutMultiplier to MAXDWORD and sets
		 ReadTotalTimeoutConstant to a value greater than zero and
		 less than MAXDWORD, one of the following occurs when the
		 ReadFile function is called:

		 If there are any bytes in the input buffer, ReadFile returns
		       immediately with the bytes in the buffer.

		 If there are no bytes in the input buffer, ReadFile waits
	               until a byte arrives and then returns immediately.

		 If no bytes arrive within the time specified by
		       ReadTotalTimeoutConstant, ReadFile times out.
	*/
	
	var timeouts structTimeouts
	err := getCommTimeouts(h, &timeouts)
	if err != nil {
		return err
	}
	
//	timeouts.ReadIntervalTimeout = MAXDWORD
//	timeouts.ReadTotalTimeoutMultiplier = MAXDWORD

	timeouts.ReadIntervalTimeout = 1000
	timeouts.ReadTotalTimeoutMultiplier = 1000
	timeouts.ReadTotalTimeoutConstant = uint32(timeoutMs)

	r, _, err := syscall.Syscall(nSetCommTimeouts, 2, uintptr(h), uintptr(unsafe.Pointer(&timeouts)), 0)
	if r == 0 {
		return err
	}
	return nil
}

func setupComm(h syscall.Handle, in, out int) error {
	r, _, err := syscall.Syscall(nSetupComm, 3, uintptr(h), uintptr(in), uintptr(out))
	if r == 0 {
		return err
	}
	return nil
}

func setCommMask(h syscall.Handle) error {
	const EV_RXCHAR = 0x0001
	r, _, err := syscall.Syscall(nSetCommMask, 2, uintptr(h), EV_RXCHAR, 0)
	if r == 0 {
		return err
	}
	return nil
}

func resetEvent(h syscall.Handle) error {
	r, _, err := syscall.Syscall(nResetEvent, 1, uintptr(h), 0, 0)
	if r == 0 {
		return err
	}
	return nil
}

//func purgeComm(h syscall.Handle) error {
//	const PURGE_TXABORT = 0x0001
//	const PURGE_RXABORT = 0x0002
//	const PURGE_TXCLEAR = 0x0004
//	const PURGE_RXCLEAR = 0x0008
//	r, _, err := syscall.Syscall(nPurgeComm, 2, uintptr(h),
//		PURGE_TXABORT|PURGE_RXABORT|PURGE_TXCLEAR|PURGE_RXCLEAR, 0)
//	if r == 0 {
//		return err
//	}
//	return nil
//}

func purgeComm(h syscall.Handle, flag int) error {
	r, _, err := syscall.Syscall(nPurgeComm, 2, uintptr(h), uintptr(flag), 0)
	if r == 0 {
		return err
	}
	return nil
}

func purgeCommTx(h syscall.Handle) error {
	const PURGE_TXABORT = 0x0001
	const PURGE_TXCLEAR = 0x0004
	r, _, err := syscall.Syscall(nPurgeComm, 2, uintptr(h),
		PURGE_TXCLEAR, 0)
	if r == 0 {
		return err
	}
	return nil
}

func purgeCommRx(h syscall.Handle) error {
	const PURGE_RXABORT = 0x0002
	const PURGE_RXCLEAR = 0x0008
	r, _, err := syscall.Syscall(nPurgeComm, 2, uintptr(h),
		PURGE_RXCLEAR, 0)
	if r == 0 {
		return err
	}
	return nil
}

func clearCommError(h syscall.Handle, e *uint, cs *structCOMSTAT) (bool, error) {
	r, _, err := syscall.Syscall(nClearCommError, 3, uintptr(h), 
		uintptr(unsafe.Pointer(e)), uintptr(unsafe.Pointer(cs)))
	if r == 0 {
		return false, err
	}
	
	return true, nil
}

func newOverlapped() (*syscall.Overlapped, error) {
	var overlapped syscall.Overlapped
	r, _, err := syscall.Syscall6(nCreateEvent, 4, 0, 1, 0, 0, 0, 0)
	if r == 0 {
		return nil, err
	}
	overlapped.HEvent = syscall.Handle(r)
	return &overlapped, nil
}

func getOverlappedResult(h syscall.Handle, overlapped *syscall.Overlapped) (int, error) {
	var n int
	r, _, err := syscall.Syscall6(nGetOverlappedResult, 4,
		uintptr(h),
		uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(&n)), 1, 0, 0)
	if r == 0 {
		return n, err
	}

	return n, nil
}
