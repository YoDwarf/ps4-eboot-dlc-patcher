using Iced.Intel;
using Spectre.Console;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;

namespace ps4_eboot_dlc_patcher;
internal static class InExecutableLoaderStuff
{
    internal static async Task<List<(ulong offset, byte[] newBytes, string description)>> GetAllInEbootPatchesForExec(Ps4ModuleLoader.Ps4Binary binary, Stream inputExecStream, int freeSpaceAtEnd, int fileOffsetOfFreeSpaceStart, IReadOnlyList<DlcInfo> dlcList)
    {
        if (dlcList.Any(x => x.EntitlementKey.Any(keyByte => keyByte != 0x0)))
        {
            if (!ConsoleUi.Confirm("Detected non-zero entitlement key(s) in DLC list. In this mode the real entitlement keys are ignored and only zeroes will be passed to the game. Continue?"))
            {
                throw new Exception("User aborted");
            }
        }

        List<string> symbolsThatRequireNewFunctions = [
            "sceAppContentGetAddcontInfoList",
            "sceAppContentGetAddcontInfo",
            "sceAppContentAddcontMount",
            "sceAppContentGetEntitlementKey",
        ];

        List<(ulong offset, byte[] newBytes, string description)> patches = new();

        int requiredBytesForPatches = 0;

        var dlcListPatchBytes = new byte[dlcList.Count * 17]; // 17 bytes -> entitlement label + status byte
        for (int i = 0; i < dlcList.Count; i++)
        {
            Encoding.ASCII.GetBytes(dlcList[i].EntitlementLabel, dlcListPatchBytes.AsSpan(i * 17, 16));
            dlcListPatchBytes[i * 17 + 16] = (byte)dlcList[i].Type;
        }

        patches.Add(((ulong)fileOffsetOfFreeSpaceStart, dlcListPatchBytes, "DLC list"));

        requiredBytesForPatches += dlcListPatchBytes.Length;

        foreach (var symbol in symbolsThatRequireNewFunctions)
        {
            var nid = Ps4ModuleLoader.Utils.CalculateNidForSymbol(symbol);
            var symbolRelocation = binary.Relocations.SingleOrDefault(x => x.SYMBOL is not null && x.SYMBOL.StartsWith(nid));
            if (symbolRelocation is null)
            {
                continue;
            }
            var rip = fileOffsetOfFreeSpaceStart + requiredBytesForPatches;
            var entitlemetsArrayAddress = fileOffsetOfFreeSpaceStart;
            var dlcCount = dlcList.Count;
            var patchBytes = symbol switch
            {
                "sceAppContentGetAddcontInfoList" => GetSceAppContentGetAddcontInfoListHandlerAsmBytes(rip, entitlemetsArrayAddress, dlcCount),
                "sceAppContentGetAddcontInfo" => GetSceAppContentGetAddcontInfoHandlerAsmBytes(rip, entitlemetsArrayAddress, dlcCount),
                "sceAppContentAddcontMount" => GetSceAppContentAddcontMountHandlerAsmBytes(rip, entitlemetsArrayAddress, dlcCount),
                "sceAppContentGetEntitlementKey" => GetSceAppContentGetEntitlementKeyHandlerAsmBytes(rip, entitlemetsArrayAddress, dlcCount),
                _ => throw new NotImplementedException(),
            };
            patches.Add(((ulong)(fileOffsetOfFreeSpaceStart + requiredBytesForPatches), patchBytes, symbol));
            requiredBytesForPatches += patchBytes.Length;
        }

        if (requiredBytesForPatches > freeSpaceAtEnd)
        {
            throw new Exception($"Not enough free space at end of file for in eboot patches. Needed {requiredBytesForPatches} but only {freeSpaceAtEnd} available");
        }

        List<string> SymbolsThatArePatchedInPlace = [
            "sceAppContentAddcontUnmount",
            "sceAppContentAddcontDelete",
        ];


        List<(string symbol, ulong? funcPtr, List<Instruction> xrefs)> symbolsWithXrefs = symbolsThatRequireNewFunctions.Concat(SymbolsThatArePatchedInPlace).Select(x => (x, binary.Relocations.SingleOrDefault(y => y.SYMBOL is not null && y.SYMBOL.StartsWith(Ps4ModuleLoader.Utils.CalculateNidForSymbol(x)))?.REAL_FUNCTION_ADDRESS, new List<Instruction>())).ToList();

        var codeSegment = binary.E_SEGMENTS.First(x => x.GetName() == "CODE"); // throws if not found

        var reader = new StreamCodeReader(inputExecStream);
        inputExecStream.Seek((long)codeSegment.OFFSET, SeekOrigin.Begin);

        var decoder = Iced.Intel.Decoder.Create(64, reader);
        decoder.IP = codeSegment.MEM_ADDR;
        int lastPercentPrinted = 0;

        var progress = new ConsoleUi.PercentProgressBar("Analyzing code segment");

        ulong memAddrPlusFileSize = codeSegment.MEM_ADDR + codeSegment.FILE_SIZE;
        while(decoder.IP < memAddrPlusFileSize)
        {
            await progress.Update((double)((double)(decoder.IP - codeSegment.MEM_ADDR) / (double)codeSegment.FILE_SIZE) * 100);
            
            decoder.Decode(out var instr);

            if (instr.Code == Code.Call_rel32_64 || instr.Code == Code.Jmp_rel32_64)
            {
                foreach (var (symbol, funcPtr, xrefs) in symbolsWithXrefs)
                {
                    if (instr.NearBranchTarget != funcPtr)
                    { continue; }


                    ConsoleUi.LogInfo($"Found call to {symbol} at 0x{instr.IP:X}");

                    xrefs.Add(instr);
                }


            }

        }

        await progress.Update(100); // just in case


        foreach (var (symbol, funcPtr, xrefs) in symbolsWithXrefs)
        {
            if (xrefs.Count == 0)
            {
                ConsoleUi.LogInfo($"No xrefs found for {symbol}");
                continue;
            }

            if (symbolsThatRequireNewFunctions.Contains(symbol))
            {
                // normally offset is the file offset but we need the memory offset
                ulong fakeFunctionEntryMem = (patches.First(x => x.description == symbol).offset - codeSegment.OFFSET) + codeSegment.MEM_ADDR;

                foreach (var xref in xrefs)
                {
                    // We're already only getting e8 and e9 calls
                    // so we always just need to patch the last 4 bytes
                    var rip = xref.IP + (ulong)xref.Length;
                    var offset = fakeFunctionEntryMem - rip;

                    byte[] offsetBytes = new byte[4];
                    BinaryPrimitives.WriteInt32LittleEndian(offsetBytes, (int)offset);

                    patches.Add((codeSegment.OFFSET + (xref.IP + 1) - codeSegment.MEM_ADDR, offsetBytes, $"Redirect call to {symbol} to fake handler"));
                }
            }
            else if (SymbolsThatArePatchedInPlace.Contains(symbol))
            {
                // instead of calling just mov eax, 0x0
                foreach (var xref in xrefs)
                {
                    // if its a jmp then xor eax, eax and ret
                    if (xref.Code == Code.Jmp_rel32_64)
                    {
                        byte[] newBytes = [0x31, 0xC0, 0x90, 0x90, 0xC3];
                        patches.Add((codeSegment.OFFSET + (xref.IP - codeSegment.MEM_ADDR), newBytes, $"Patch out jmp to {symbol}"));
                    }
                    else if (xref.Code == Code.Call_rel32_64)
                    {
                        patches.Add((codeSegment.OFFSET + (xref.IP - codeSegment.MEM_ADDR), new byte[] { 0xB8, 0x00, 0x00, 0x00, 0x00 }, $"Patch out call to {symbol}"));
                    }
                    else
                    {
                        throw new UnreachableException("Unknown opcode");
                    }
                }
            }
            else
            {
                throw new UnreachableException();
            }
        }

        return patches;
    }


    public static byte[] GetSceAppContentAddcontMountHandlerAsmBytes(int rip, int entitlementsArrayAddress, int dlcCount)
    {
        // zero out mountpoint buffer (16 bytes) and set up stuff for loop
        //xor rax,rax
        //mov qword ptr [rdx], rax
        //mov qword ptr [rdx+8], rax
        //lea rdi, [rip+0x60] # replace 0x60 with offset to entitlements array
        //mov rax, qword ptr [rsi]
        //mov r8, qword ptr [rsi+8]
        //xor rcx, rcx

        // compare EntitlementLabel arg with each entry in the entitlements array
        //loop:
        //cmp qword ptr [rdi], rax
        //jne loop_next
        //cmp qword ptr [rdi+8], r8
        //jne loop_next
        //jmp match_found

        //loop_next:
        //inc rcx
        //cmp rcx, 3 # replace 3 with dlc count
        //je ret_no_entitlement
        //add rdi, 17
        //jmp loop

        // return early if not installed (which is for no extra data dlc types in this scenario)
        //match_found:
        //cmp byte ptr [rdi+16], 0x04 # if not SCE_APP_CONTENT_ADDCONT_DOWNLOAD_STATUS_INSTALLED
        //je set_mountpoint
        //mov eax, 0x80D90004 # SCE_APP_CONTENT_ERROR_NOT_MOUNTED
        //ret

        // first copy in static text which is /app0/dlc then append the counter number as two digits
        //set_mountpoint:
        //mov dword ptr [rdx], 0x7070612F
        //mov dword ptr [rdx+4], 0x6C642F30
        //mov byte ptr [rdx+8], 0x63

        //mov r8, rdx # since div will write to rdx, and we still need to write to the buffer later
        //mov eax, ecx
        //xor edx, edx
        //mov ecx, 10
        //div ecx

        //add al, 0x30
        //mov byte ptr [r8+9], al
        //add dl, 0x30
        //mov byte ptr [r8+10], dl
        //xor eax, eax
        //ret

        //ret_no_entitlement: # SCE_APP_CONTENT_ERROR_DRM_NO_ENTITLEMENT
        //mov eax, 0x80D90007
        //ret

        if (dlcCount > 99)
        {
            throw new ArgumentOutOfRangeException(nameof(dlcCount), "DLC count must be less than 100 for in eboot handler");
        }

        int rdiTarget = entitlementsArrayAddress - (rip + 0x11);
        byte[] rdiTargetBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(rdiTargetBytes, rdiTarget);
        return new byte[] { 0x48, 0x31, 0xC0, 0x48, 0x89, 0x02, 0x48, 0x89, 0x42, 0x08, 0x48, 0x8D, 0x3D }.Concat(rdiTargetBytes).Concat(new byte[] { 0x48, 0x8B, 0x06, 0x4C, 0x8B, 0x46, 0x08, 0x48, 0x31, 0xC9, 0x48, 0x39, 0x07, 0x75, 0x08, 0x4C, 0x39, 0x47, 0x08, 0x75, 0x02, 0xEB, 0x0F, 0x48, 0xFF, 0xC1, 0x48, 0x83, 0xF9, (byte)dlcCount, 0x74, 0x41, 0x48, 0x83, 0xC7, 0x11, 0xEB, 0xE4, 0x80, 0x7F, 0x10, 0x04, 0x74, 0x06, 0xB8, 0x04, 0x00, 0xD9, 0x80, 0xC3, 0xC7, 0x02, 0x2F, 0x61, 0x70, 0x70, 0xC7, 0x42, 0x04, 0x30, 0x2F, 0x64, 0x6C, 0xC6, 0x42, 0x08, 0x63, 0x49, 0x89, 0xd0, 0x89, 0xC8, 0x31, 0xD2, 0xB9, 0x0A, 0x00, 0x00, 0x00, 0xF7, 0xF1, 0x04, 0x30, 0x41, 0x88, 0x40, 0x09, 0x80, 0xC2, 0x30, 0x41, 0x88, 0x50, 0x0A, 0x31, 0xC0, 0xC3, 0xB8, 0x07, 0x00, 0xD9, 0x80, 0xC3 }).ToArray();

    }

    public static byte[] GetSceAppContentGetAddcontInfoListHandlerAsmBytes(int rip, int entitlementsArrayAddress, int dlcCount)
    {
        //    mov r8d, 1 # replace 1 with dlc count
        //    test edx, edx
        //    jz handle_null
        //    cmp edx, r8d # take the smaller, either real dlc count or listNum (we know listNum isnt 0 here)
        //    cmovb r8d, edx
        //    mov dword ptr [rcx], r8d
        //    lea rdx, [rip + 0x60] # replace 0x60 with offset to entitlements array
        //loop:
        //        mov rax, qword ptr [rdx]
        //        mov qword ptr [rsi], rax
        //        mov rax, qword ptr [rdx+8]
        //        mov qword ptr [rsi+8], rax
        //        xor rax, rax
        //        mov qword ptr [rsi+16], rax
        //        mov al, byte ptr [rdx+16] # rax is already zeroed out and so is rsi+16 to 24
        //        mov byte ptr [rsi+20], al
        //        add rsi, 24
        //        add rdx, 17
        //        dec r8d
        //        jnz loop
        //        jmp end
        //handle_null:
        //    mov dword ptr [rcx], r8d
        //end:
        //    xor eax, eax
        //    ret


        int rdxTarget = entitlementsArrayAddress - (rip + 0x1b);
        byte[] rdxTargetBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(rdxTargetBytes, rdxTarget);

        byte[] littleEndianDlcCount = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(littleEndianDlcCount, dlcCount);
        return new byte[] { 0x41, 0xB8 }.Concat(littleEndianDlcCount).Concat(new byte[] { 0x85, 0xD2, 0x74, 0x3B, 0x44, 0x39, 0xC2, 0x44, 0x0F, 0x42, 0xC2, 0x44, 0x89, 0x01, 0x48, 0x8D, 0x15 }).Concat(rdxTargetBytes).Concat(new byte[] { 0x48, 0x8B, 0x02, 0x48, 0x89, 0x06, 0x48, 0x8B, 0x42, 0x08, 0x48, 0x89, 0x46, 0x08, 0x48, 0x31, 0xC0, 0x48, 0x89, 0x46, 0x10, 0x8A, 0x42, 0x10, 0x88, 0x46, 0x14, 0x48, 0x83, 0xC6, 0x18, 0x48, 0x83, 0xC2, 0x11, 0x41, 0xFF, 0xC8, 0x75, 0xD8, 0xEB, 0x03, 0x44, 0x89, 0x01, 0x31, 0xC0, 0xC3 }).ToArray();
    }

    public static byte[] GetSceAppContentGetAddcontInfoHandlerAsmBytes(int rip, int entitlementsArrayAddress, int dlcCount)
    {
        //lea rdi, [rip+0x60] # replace 0x60 with offset to entitlements array
        //mov rax, qword ptr [rsi]
        //mov r8, qword ptr [rsi+8]
        //xor ecx, ecx

        //loop:
        //cmp qword ptr [rdi], rax
        //jne loop_next
        //cmp qword ptr [rdi+8], r8
        //jne loop_next
        //jmp match_found

        //loop_next:
        //inc ecx
        //cmp ecx, 3 # replace 3 with dlc count
        //je ret_no_entitlement
        //add rdi, 17
        //jmp loop

        //match_found:
        //mov qword ptr [rdx], rax
        //mov qword ptr [rdx+8], r8
        //xor rax, rax
        //mov qword ptr [rdx+16], rax # null terminate string zero out 3 byte padding and zero out 4 byte int status
        //mov al, byte ptr [rdi+16] # status byte
        //mov byte ptr [rdx+20], al 
        //xor eax, eax
        //ret

        //ret_no_entitlement: # SCE_APP_CONTENT_ERROR_DRM_NO_ENTITLEMENT
        //mov eax, 0x80D90007
        //ret

        if (dlcCount > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(dlcCount), $"DLC count must be less than {byte.MaxValue} for in eboot handler");
        }

        int rdiTarget = entitlementsArrayAddress - (rip + 0x07);
        byte[] rdiTargetBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(rdiTargetBytes, rdiTarget);

        return new byte[] { 0x48, 0x8D, 0x3D }.Concat(rdiTargetBytes).Concat(new byte[] { 0x48, 0x8B, 0x06, 0x4C, 0x8B, 0x46, 0x08, 0x31, 0xC9, 0x48, 0x39, 0x07, 0x75, 0x08, 0x4C, 0x39, 0x47, 0x08, 0x75, 0x02, 0xEB, 0x0D, 0xFF, 0xC1, 0x83, 0xF9, (byte)dlcCount, 0x74, 0x1D, 0x48, 0x83, 0xC7, 0x11, 0xEB, 0xE6, 0x48, 0x89, 0x02, 0x4C, 0x89, 0x42, 0x08, 0x48, 0x31, 0xC0, 0x48, 0x89, 0x42, 0x10, 0x8A, 0x47, 0x10, 0x88, 0x42, 0x14, 0x31, 0xC0, 0xC3, 0xB8, 0x07, 0x00, 0xD9, 0x80, 0xC3 }).ToArray();
    }

    /// <summary>
    /// Only zeroes out the key buffer if the entitlement label is found, returns SCE_APP_CONTENT_ERROR_DRM_NO_ENTITLEMENT if not found
    /// </summary>
    /// <param name="rip"></param>
    /// <param name="entitlementsArrayAddress"></param>
    /// <param name="dlcCount"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static byte[] GetSceAppContentGetEntitlementKeyHandlerAsmBytes(int rip, int entitlementsArrayAddress, int dlcCount)
    {
        //lea rdi, [rip+0x60] # replace 0x60 with offset to entitlements array
        //mov rax, qword ptr [rsi]
        //mov r8, qword ptr [rsi+8]
        //xor ecx, ecx

        //loop:
        //cmp qword ptr [rdi], rax
        //jne loop_next
        //cmp qword ptr [rdi+8], r8
        //jne loop_next
        //jmp match_found

        //loop_next:
        //inc ecx
        //cmp ecx, 3 # replace 3 with dlc count
        //je ret_no_entitlement
        //add rdi, 17
        //jmp loop

        //match_found:
        //xor rax, rax
        //mov qword ptr [rdx], rax # zero out key buffer
        //mov qword ptr [rdx+8], rax
        //ret # rax already 0

        //ret_no_entitlement: # SCE_APP_CONTENT_ERROR_DRM_NO_ENTITLEMENT
        //mov eax, 0x80D90007
        //ret

        if (dlcCount > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(dlcCount), $"DLC count must be less than {byte.MaxValue} for in eboot handler");
        }

        int rdiTarget = entitlementsArrayAddress - (rip + 0x07);
        byte[] rdiTargetBytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(rdiTargetBytes, rdiTarget);

        return new byte[] { 0x48, 0x8D, 0x3D }.Concat(rdiTargetBytes).Concat(new byte[] { 0x48, 0x8B, 0x06, 0x4C, 0x8B, 0x46, 0x08, 0x31, 0xC9, 0x48, 0x39, 0x07, 0x75, 0x08, 0x4C, 0x39, 0x47, 0x08, 0x75, 0x02, 0xEB, 0x0D, 0xFF, 0xC1, 0x83, 0xF9, (byte)dlcCount, 0x74, 0x11, 0x48, 0x83, 0xC7, 0x11, 0xEB, 0xE6, 0x48, 0x31, 0xC0, 0x48, 0x89, 0x02, 0x48, 0x89, 0x42, 0x08, 0xC3, 0xB8, 0x07, 0x00, 0xD9, 0x80, 0xC3 }).ToArray();
    }



}
