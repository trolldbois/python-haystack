from winappdbg.win32 import *

def print_heap_blocks( pid ):
    # Determine if we have 32 bit or 64 bit pointers
    if sizeof(SIZE_T) == sizeof(DWORD):
        fmt = "%.8x\t%.8x\t%.8x"
        hdr = "%-8s\t%-8s\t%-8s"
    else:
        fmt = "%.16x\t%.16x\t%.16x"
        hdr = "%-16s\t%-16s\t%-16s"
    # Print a banner
    print "Heaps for process %d:" % pid
    print hdr % ("Heap ID", "Address", "Size")
    # Create a snapshot of the process, only take the heap list
    hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPHEAPLIST, pid )
    # Enumerate the heaps
    heap = Heap32ListFirst( hSnapshot )
    while heap is not None:
        # For each heap, enumerate the entries
        entry = Heap32First( heap.th32ProcessID, heap.th32HeapID )
        while entry is not None:
            # Print the heap id and the entry address and size
            print fmt % (entry.th32HeapID, entry.dwAddress, entry.dwBlockSize)
            # Next entry in the heap
            entry = Heap32Next( entry )
        # Next heap in the list
        heap = Heap32ListNext( hSnapshot )
    # No need to call CloseHandle, the handle is closed automatically when it goes out of scope
    return