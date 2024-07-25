# CLSbombing
A novel process injection technique based on the classical Atombombing technique. Instead of the global atom table, we use the tagCLS structure.

![image](https://github.com/user-attachments/assets/9b1f77b9-6412-4ae2-8306-5b6e37753a27)

## Compilation
Compiled with mingw GCC using `x86_64-w64-mingw32-gcc main.c`

## Process
1. We put a marker in tagCLS via `SetClassLongPtrA`, then we scan own process memory for it. This is to find the offset from the beginning of tagCLS.
2. Next, we enumerate the target process memory. Using `VirtualQueryEx`, we scan for a memory region with same size, MEM_MAPPED, PAGE_READONLY features. This is basically guaranteed to be tagCLS.
3. We add the offset to the beginning of tagCLS structure. Now, we insert the actual shellcode into tagCLS. Hence, we have the shellcode mapped inside tagCLS memory in the target process, along with its offset.
4. We create a thread in the process, and use `VirtualAllocEx` and `RtlMoveMemory` to copy the data from tagCLS into an executable region. This is necessary as we cannot change the protections of the tagCLS region itself.
5. Now, we can run the shellcode! We create another thread in the process to do so.

## Potential improvements
Can definitely make the steps 4-5 less noisy. This can be accomplished with the use of a ROP chain, I just opted to not do so as the common Windows DLLs seem to be quite lacking in usable gadgets, so to reduce complexity, I do not use ROPs.
