from __future__ import print_function
from winappdbg import win32
import ctypes

def print_heap_blocks(pid):
    # Determine if we have 32 bit or 64 bit pointers
    if ctypes.sizeof(win32.SIZE_T) == ctypes.sizeof(win32.DWORD):
        fmt = "%.8x\t%.8x\t%.8x"
        hdr = "%-8s\t%-8s\t%-8s"
    else:
        fmt = "%.16x\t%.16x\t%.16x"
        hdr = "%-16s\t%-16s\t%-16s"
    # Print a banner
    print("Heaps for process %d:" % pid)
    print(hdr % ("Heap ID", "Address", "Size"))
    # Create a snapshot of the process, only take the heap list
    hSnapshot = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPHEAPLIST, pid)
    # Enumerate the heaps
    heap = win32.Heap32ListFirst(hSnapshot)
    while heap is not None:
        # For each heap, enumerate the entries
        entry = win32.Heap32First(heap.th32ProcessID, heap.th32HeapID)
        while entry is not None:
            # Print the heap id and the entry address and size
            print(fmt % (entry.th32HeapID, entry.dwAddress, entry.dwBlockSize))
            # Next entry in the heap
            entry = win32.Heap32Next(entry)
        # Next heap in the list
        heap = win32.Heap32ListNext(hSnapshot)
    # No need to call CloseHandle, the handle is closed automatically when it
    # goes out of scope
    return
