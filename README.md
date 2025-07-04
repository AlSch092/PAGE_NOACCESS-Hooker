# PAGE_NOACCESS Hooker
An interesting technique on Windows (x64) to "hook" or breakpoint in process memory via VEH and PAGE_NOACCESS page permissions

## Use Case
The technique is useful in cases where you cannot easily write to memory, either due to integrity checks, re-mapped memory with `SEC_NO_CHANGE`, or kernelmode protections. It can also be used for debugging. I've used it for logging & modifying game packets in a few games including MapleStoryN which uses a kernelmode AC; many usermode ACs also won't detect this since it's not using standard/traditional debugging methods. 

## How it works  
1. We inject the module using a manual mapper, or some other stealthy method   
2. The program reads `breakpoints.txt` for a list of desired addresses to 'hook'/breakpoint  
3. A VEH handler is created, and each offset's page is marked with `PAGE_NOACCESS`  
4. When process execution hits somewhere on that page, our VEH handler is executed, where we can read/write to registers or other memory in RAM  
5. Our handler restores original page protections to allow execution to resume, while another thread in our DLL re-places the `PAGE_NOACCESS` permissions (its best if this thread is created using stealthier methods than explicitly calling `CreateThread`, but I'll leave this to the reader)   
6. If execution hits somewhere else on the same page as our desired offset, we can single step through until we hit our desired address, or simply resume execution  

## Downsides & Warnings  
There's no guarantee that what you test this on will or won't detect the technique. This repo is meant to serve as a proof of concept for an alternative method to traditional hooking. If extreme care is not taken, the process will probably crash, so make sure you know what you're doing. In cases where your desired offset has other addresses on the same page rapidly hit during execution, this might not be a good method to use. This is definitely best used for purposes such as packet logging/modifying, or basic runtime analysis.  

## Example  
MapleStoryN, injected via manual mapping before its kernelmode driver is loaded:  
![Example](https://github.com/user-attachments/assets/dc22e34f-7f73-4c7a-ab0f-295c2c27c633)  

Happy coding!  

