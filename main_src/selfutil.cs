namespace SelfUtil;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

/// <summary>
/// Port of https://github.com/xSpecialFoodx/SelfUtil-Patched/tree/53ca642bfe5d809550db22bc1c1d36cd4208ab8b
/// </summary>
public class SelfUtil
{
    public enum LogLevel
    {
        None,
        Regular,
        Verbose
    }
    public LogLevel logLevel = LogLevel.None;

    bool align_size = false;
    bool patch_first_segment_duplicate = true;
    float patch_first_segment_safety_percentage = 2; // min amount of cells (in percentage) that should fit in other words
    bool patch_version_segment = true;

    int first_min_offset = -1;

    Stream dataStream;

    List<Self.Self_Entry>? entries;

    Elf.Elf64_Ehdr? eHead;
    ulong elfHOffs;

    List<Elf.Elf64_Phdr> phdrs = new();

    public SelfUtil(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: \"{filePath}\"");
        }

        dataStream = File.OpenRead(filePath);

        if (!Parse())
        {
            throw new Exception("Failed to parse file!");
        }
    }

    public SelfUtil(Stream stream)
    {
        dataStream = stream;

        if (!Parse())
        {
            throw new Exception("Failed to parse file!");
        }
    }

    public enum FileType
    {
        Unknown,
        Uelf,
        Ps4Self,
        Ps5Self // this is for the future i guess, ps5 dumps still use ps4 self magic
    }

    public static FileType GetFileType(string filePath)
    {
        if (!File.Exists(filePath))
        { return FileType.Unknown; }

        using var fs = File.OpenRead(filePath);

        fs.Seek(0, SeekOrigin.Begin);

        byte[] magicBytes = new byte[4];
        fs.Read(magicBytes, 0, 4);

        return GetFileType(magicBytes);
    }

    public static FileType GetFileType(byte[] fourByteMagic)
    {
        if (fourByteMagic is null || fourByteMagic.Length != 4)
        { throw new ArgumentException("Invalid magic bytes!"); }

        if (fourByteMagic.SequenceEqual(Self.ELF_MAGIC))
        { return FileType.Uelf; }
        else if (fourByteMagic.SequenceEqual(Self.PS4_SELF_MAGIC))
        { return FileType.Ps4Self; }
        else if (fourByteMagic.SequenceEqual(Self.PS5_SELF_MAGIC))
        { return FileType.Ps5Self; }

        return FileType.Unknown;
    }

    public bool Parse()
    {
        Self.Self_Hdr seHead = new(SelfUtil.ReadBytes(dataStream, 0, Marshal.SizeOf<Self.Self_Hdr>()));

        if (seHead.magic.SequenceEqual(Self.PS4_SELF_MAGIC))
        {
            if (logLevel >= LogLevel.Verbose) { Console.WriteLine("Valid PS4 Magic"); }

            if (dataStream.Length < Self.PS4_PAGE_SIZE && logLevel >= LogLevel.Verbose)
            { Console.WriteLine($"Small file size! ({dataStream.Length})\nContinuing regardless."); }
        }
        else if (seHead.magic.SequenceEqual(Self.PS5_SELF_MAGIC))
        {
            if (logLevel >= LogLevel.Verbose) { Console.WriteLine("Valid PS5 Magic"); }

            if (dataStream.Length < Self.PS5_PAGE_SIZE && logLevel >= LogLevel.Verbose)
            { Console.WriteLine($"Small file size! ({dataStream.Length})\nContinuing regardless."); }
        }
        else
        {
            if (logLevel >= LogLevel.Regular)
            { Console.WriteLine($"Invalid Magic! (0x{seHead.magic:X8})"); }
            return false;
        }

        entries = new();
        for (uint seIdx = 0; seIdx < seHead.num_entries; seIdx++)
        {
            byte[] entryBytes = ReadBytes(dataStream, (1 + seIdx) * Marshal.SizeOf<Self.Self_Entry>(), Marshal.SizeOf<Self.Self_Entry>());
            entries.Add(new Self.Self_Entry(entryBytes));

            var se = entries.Last();

            if (logLevel >= LogLevel.Verbose)
            {
                Console.Write($"Segment[{seIdx:D2}] P: {se.props:X08} ");
                Console.Write($"(id: {(se.props >> 20):X}) ");
                Console.WriteLine($"@ 0x{se.offs:X016} +{se.fileSz:X016} (mem: {se.memSz:X})");
            }
        }

        elfHOffs = (ulong)(1 + seHead.num_entries) * 0x20;

        eHead = new Elf.Elf64_Ehdr(SelfUtil.ReadBytes(dataStream, (long)elfHOffs, Marshal.SizeOf<Elf.Elf64_Ehdr>()));

        if (!TestIdent())
        {
            if (logLevel >= LogLevel.Regular)
            { Console.WriteLine("Elf e_ident invalid!"); }
            return false;
        }

        for (uint phIdx = 0; phIdx < eHead.e_phnum; phIdx++)
        {
            byte[] phdrBytes = SelfUtil.ReadBytes(dataStream, (long)(elfHOffs + eHead.e_phoff) + (long)(phIdx * eHead.e_phentsize), (int)eHead.e_phentsize);
            phdrs.Add(new Elf.Elf64_Phdr(phdrBytes));
        }

        return true;
    }

    public bool TestIdent()
    {
        if (!eHead!.e_ident.AsSpan().Slice(0,4).SequenceEqual(Self.ELF_MAGIC))
        {
            if (logLevel >= LogLevel.Regular)
            { Console.WriteLine($"File is invalid! e_ident magic: 0x{BitConverter.ToUInt32(eHead.e_ident, 0):X8}"); }
            return false;
        }

        if (!((eHead.e_ident[Elf.EI_CLASS] == Elf.ELFCLASS64) &&
              (eHead.e_ident[Elf.EI_DATA] == Elf.ELFDATA2LSB) &&
              (eHead.e_ident[Elf.EI_VERSION] == Elf.EV_CURRENT) &&
              (eHead.e_ident[Elf.EI_OSABI] == Elf.ELFOSABI_FREEBSD)))
        { return false; }

        if ((eHead.e_type >> 8) != 0xFE && logLevel >= LogLevel.Regular)
        { Console.WriteLine($"Elf64::e_type: 0x{(eHead.e_type & 0xFFFF):X4}"); }

        if (!((eHead.e_machine == Elf.EM_X86_64) && (eHead.e_version == Elf.EV_CURRENT)))
        { return false; }

        return true;
    }

    public bool SaveToELF(string savePath)
    {
        using FileStream outputStream = new(savePath, FileMode.Create, FileAccess.ReadWrite);

        return SaveToELF(outputStream);
    }

    public bool SaveToELF(Stream outputStream)
    {
        Elf.Elf64_Off first, last;
        ulong saveSize;
        Elf.Elf64_Phdr? ph_first = null, ph_last = null, ph_PT_SCE_VERSION = null;
        bool patched_PT_SCE_VERSION = false;

        foreach (var ph in phdrs)
        {
            if (ph.p_type == Self.PT_SCE_VERSION)
            { ph_PT_SCE_VERSION = ph; }

            if (ph_first == null ||
                ph_first.p_offset == 0 || // try to get away from offset 0
                (
                    // if the current first ph is not null and its offset is bigger than 0
                    // , then replace it only with a smaller ph that its offset is also bigger than 0
                    ph.p_offset > 0 &&
                    ph.p_offset < ph_first.p_offset)
                )
            { ph_first = ph; }

            if (ph_last == null || ph.p_offset > ph_last.p_offset)
            { ph_last = ph; }
        }

        if (ph_first == null)
        { first = 0; }
        else
        { first = ph_first.p_offset; }

        if (ph_last == null)
        {
            last = 0;
            saveSize = 0;
        }
        else
        {
            last = ph_last.p_offset;
            saveSize = (ulong)(ph_last.p_offset + ph_last.p_filesz);

            if (align_size)
            { saveSize = (ulong)AlignUp((int)saveSize, 0x10); } // original selfutil used PS4_PAGE_SIZE alignment
        }

        if (logLevel >= LogLevel.Verbose)
        {
            Console.WriteLine();
            Console.WriteLine($"Save Size: {saveSize} bytes (0x{saveSize:X})");
            Console.WriteLine($"first: 0x{(ulong)first:X}, last: 0x{(ulong)last:X}");
        }

        outputStream.SetLength((long)saveSize);
        dataStream.Seek((long)elfHOffs, SeekOrigin.Begin);
        outputStream.Seek(0, SeekOrigin.Begin);
        CopyStream(dataStream, outputStream, Math.Min((int)first, dataStream.Length - (int)elfHOffs));
        outputStream.Flush();

        foreach (var ee in entries!)
        {
            bool method_found = false;
            uint phIdx = (uint)(ee.props >> 20) & 0xFFF;

            var ph = phdrs[(int)phIdx];

            if ((ee.props & 0x800) == 0)
            {
                if (ph_PT_SCE_VERSION != null && ph == ph_PT_SCE_VERSION && patch_version_segment)
                { method_found = true; }
            }
            else
            { method_found = true; }

            if (method_found)
            {
                method_found = false;

                if (ph.p_filesz != 0 && ph.p_filesz != ee.memSz && logLevel >= LogLevel.Verbose)
                { Console.WriteLine($"idx: {phIdx:D} SEGMENT size: {(ulong)ee.memSz} != phdr size: {ph.p_filesz}"); }

                if (ph_PT_SCE_VERSION != null && ph == ph_PT_SCE_VERSION)
                {
                    patched_PT_SCE_VERSION = true;

                    if (logLevel >= LogLevel.Regular)
                    {
                        Console.WriteLine();
                        Console.WriteLine("patching version segment");
                    }

                    if (logLevel >= LogLevel.Verbose)
                    { Console.WriteLine($"segment address: {dataStream.Length - (int)ph.p_filesz:X8}\tsegment size: {(ulong)ph.p_filesz:X8}"); }

                    dataStream.Seek(dataStream.Length - (int)ph.p_filesz, SeekOrigin.Begin);
                    outputStream.Seek((int)ph.p_offset, SeekOrigin.Begin);
                    CopyStream(dataStream, outputStream, (int)ph.p_filesz);

                    if (logLevel >= LogLevel.Regular)
                    { Console.WriteLine("patched version segment"); }
                }
                else
                {
                    dataStream.Seek((long)ee.offs, SeekOrigin.Begin);
                    outputStream.Seek((int)ph.p_offset, SeekOrigin.Begin);
                    CopyStream(dataStream, outputStream, (long)ee.fileSz);
                }
            }
        }

        if (patch_version_segment && !patched_PT_SCE_VERSION && ph_PT_SCE_VERSION != null)
        {
            if (logLevel >= LogLevel.Regular)
            {
                Console.WriteLine();
                Console.WriteLine("patching version segment");
            }

            if (logLevel >= LogLevel.Verbose)
            { Console.WriteLine($"segment address: {dataStream.Length - (int)ph_PT_SCE_VERSION.p_filesz:X8}\tsegment size: {(ulong)ph_PT_SCE_VERSION.p_filesz:X8}"); }

            dataStream.Seek(dataStream.Length - (int)ph_PT_SCE_VERSION.p_filesz, SeekOrigin.Begin);
            outputStream.Seek((int)ph_PT_SCE_VERSION.p_offset, SeekOrigin.Begin);
            CopyStream(dataStream, outputStream, (int)ph_PT_SCE_VERSION.p_filesz);

            if (logLevel >= LogLevel.Regular)
            { Console.WriteLine("patched version segment"); }
        }

        if (patch_first_segment_duplicate)
        {
            foreach (var ee in entries)
            {
                if (ee.offs - elfHOffs >= 0 && ee.offs - elfHOffs < first)
                {
                    if (first_min_offset == -1 || ee.offs - elfHOffs > (ulong)first_min_offset)
                    { first_min_offset = (int)(ee.offs - elfHOffs); }
                }
            }

            if (first_min_offset != -1 && SelfUtil.ReadBytes(outputStream, (long)first_min_offset, 1)[0] == 0)
            {
                // go forward looking for data
                for (int pd_index = 1; (ulong)(first_min_offset + pd_index) < first; pd_index++)
                {
                    if (SelfUtil.ReadBytes(outputStream, (long)(first_min_offset + pd_index), 1)[0] != 0)
                    {
                        first_min_offset += pd_index - 1;
                        break;
                    }
                }
            }

            for (int first_index = 0; (first_min_offset == -1 || first_index < first_min_offset) &&
                 (first_index < ((float)(int)first * ((float)(100 - patch_first_segment_safety_percentage) / 100)) &&
                  first - first_index >= 0x000000C0);
                 first_index++)
            {
                var count = first - first_index >= 0x000000C0 ? 0x000000C0 : first - first_index;
                byte[] compareBytes = SelfUtil.ReadBytes(outputStream, first_index, count);
                byte[] targetBytes = SelfUtil.ReadBytes(outputStream, (long)first, count);
                if (Enumerable.SequenceEqual(compareBytes, targetBytes))
                {
                    first_min_offset = first_index;
                    break;
                }
            }

            if (first_min_offset != -1)
            {
                if (logLevel >= LogLevel.Regular)
                {
                    Console.WriteLine();
                    Console.WriteLine("patching first segment duplicate");
                }

                if (logLevel >= LogLevel.Verbose)
                { Console.WriteLine($"address: 0x{first_min_offset:X8}\tsize: 0x{first - first_min_offset:X8}"); }

                outputStream.Seek(first_min_offset, SeekOrigin.Begin);
                for (int i = 0; i < (int)(first - first_min_offset); i++)
                { outputStream.WriteByte(0); }

                if (logLevel >= LogLevel.Regular)
                { Console.WriteLine("patched first segment duplicate"); }
            }
        }


        return true;
    }

    public static T AlignUp<T>(T addr, T align) where T : struct, IConvertible
    {
        dynamic pow2Mask = align - (dynamic)1;
        return (addr + pow2Mask) & ~pow2Mask;
    }

    private static byte[] ReadBytes(Stream stream, long offset, int count)
    {
        stream.Seek(offset, SeekOrigin.Begin);
        byte[] buffer = new byte[count];
        stream.ReadExactly(buffer, 0, count);
        return buffer;
    }

    private static void CopyStream(Stream input, Stream output, long length)
    {
        byte[] buffer = new byte[4096];
        int bytesRead;
        long totalBytesRead = 0;

        while ((bytesRead = input.Read(buffer, 0, (int)Math.Min(length - totalBytesRead, buffer.Length))) > 0)
        {
            output.Write(buffer, 0, bytesRead);
            totalBytesRead += bytesRead;
        }
    }












    internal class Self
    {
        public struct Self_Hdr // '<4s4B'
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] magic;
            public byte version;
            public byte mode;
            public byte endian;
            public byte attribs;
            //}
            //public struct Self_ExtHdr // '<I2HQ2H4x'
            //{
            public uint key_type;
            public ushort header_size;
            public ushort meta_size;
            public ulong file_size;
            public ushort num_entries;
            public ushort flags;
            //public byte[] pad;

            public Self_Hdr(Span<byte> data)
            {
                magic = data.Slice(0, 4).ToArray();
                version = data[4];
                mode = data[5];
                endian = data[6];
                attribs = data[7];
                key_type = BitConverter.ToUInt32(data.Slice(8, 4));
                header_size = BitConverter.ToUInt16(data.Slice(12, 2));
                meta_size = BitConverter.ToUInt16(data.Slice(14, 2));
                file_size = BitConverter.ToUInt64(data.Slice(16, 8));
                num_entries = BitConverter.ToUInt16(data.Slice(24, 2));
                flags = BitConverter.ToUInt16(data.Slice(26, 2));
                //pad = data.Slice(28, 4).ToArray();
            }
        }

        public struct Self_Entry
        {
            public ulong props;
            public ulong offs;
            public ulong fileSz;
            public ulong memSz;

            public Self_Entry(Span<byte> bytes)
            {
                props = BitConverter.ToUInt64(bytes.Slice(0, 8));
                offs = BitConverter.ToUInt64(bytes.Slice(8, 8));
                fileSz = BitConverter.ToUInt64(bytes.Slice(16, 8));
                memSz = BitConverter.ToUInt64(bytes.Slice(24, 8));
            }
        }


        public const int PS4_PAGE_SIZE = 0x4000;
        public const int PS5_PAGE_SIZE = 0x4000;

        public const int PS4_PAGE_MASK = 0x3FFF;
        public const int PS5_PAGE_MASK = 0x3FFF;

        public static readonly byte[] ELF_MAGIC = [0x7F, (byte)'E', (byte)'L', (byte)'F'];

        public static readonly byte[] PS4_SELF_MAGIC = [0x4F, 0x15, 0x3D, 0x1D];

        public static readonly byte[] PS5_SELF_MAGIC = [0x54, 0x14, 0xF5, 0xEE];

        // ExInfo::ptype
        public const int SELF_PT_FAKE = 0x1;
        public const int SELF_PT_NPDRM_EXEC = 0x4;
        public const int SELF_PT_NPDRM_DYNLIB = 0x5;
        public const int SELF_PT_SYSTEM_EXEC = 0x8;
        public const int SELF_PT_SYSTEM_DYNLIB = 0x9; // including Mono binaries
        public const int SELF_PT_HOST_KERNEL = 0xC;
        public const int SELF_PT_SEC_MODULE = 0xE;
        public const int SELF_PT_SEC_KERNEL = 0xF;

        /* SCE-specific definitions for e_type: */
        public const ushort ET_SCE_EXEC = 0xFE00;         /* SCE Executable file */
        // ET_SCE_REPLAY_EXEC = 0xfe01
        public const ushort ET_SCE_RELEXEC = 0xFE04;      /* SCE Relocatable Executable file */
        public const ushort ET_SCE_STUBLIB = 0xFE0C;      /* SCE SDK Stubs */
        public const ushort ET_SCE_DYNEXEC = 0xFE10;      /* SCE EXEC_ASLR */
        public const ushort ET_SCE_DYNAMIC = 0xFE18;      /* Unused */
        public const ushort ET_SCE_PSPRELEXEC = 0xFFA0;   /* Unused (PSP ELF only) */
        public const ushort ET_SCE_PPURELEXEC = 0xFFA4;   /* Unused (SPU ELF only) */
        public const ushort ET_SCE_UNK = 0xFFA5;          /* Unknown */

        /* ?? */
        public const int PT_SCE_RELA = Elf.PT_LOOS;  // .rela No +0x1000000 ?

        public const int PT_SCE_DYNLIBDATA = Elf.PT_LOOS + 0x1000000; // .sce_special
        public const int PT_SCE_PROCPARAM = Elf.PT_LOOS + 0x1000001;   // .sce_process_param
        public const int PT_SCE_RELRO = Elf.PT_LOOS + 0x1000010;       // .data.rel.ro
        public const int PT_SCE_COMMENT = Elf.PT_LOOS + 0xfffff00;     // .sce_comment
        public const int PT_SCE_VERSION = Elf.PT_LOOS + 0xfffff01;     // .sce_version

        public const uint PT_GNU_EH_FRAME = 0x6474E550;  // .eh_frame_hdr
        public const uint PT_GNU_STACK = 0x6474E551;

        /* SCE_PRIVATE: bug 63164, add for objdump */
        public const uint DT_SCE_IDTABENTSZ = 0x61000005;
        public const uint DT_SCE_FINGERPRINT = 0x61000007;
        public const uint DT_SCE_ORIGINAL_FILENAME = 0x61000009;
        public const uint DT_SCE_MODULE_INFO = 0x6100000D;
        public const uint DT_SCE_NEEDED_MODULE = 0x6100000F;
        public const uint DT_SCE_MODULE_ATTR = 0x61000011;
        public const uint DT_SCE_EXPORT_LIB = 0x61000013;
        public const uint DT_SCE_IMPORT_LIB = 0x61000015;
        public const uint DT_SCE_EXPORT_LIB_ATTR = 0x61000017;
        public const uint DT_SCE_IMPORT_LIB_ATTR = 0x61000019;
        public const uint DT_SCE_STUB_MODULE_NAME = 0x6100001D;
        public const uint DT_SCE_STUB_MODULE_VERSION = 0x6100001F;
        public const uint DT_SCE_STUB_LIBRARY_NAME = 0x61000021;
        public const uint DT_SCE_STUB_LIBRARY_VERSION = 0x61000023;
        public const uint DT_SCE_HASH = 0x61000025;
        public const uint DT_SCE_PLTGOT = 0x61000027;
        public const uint DT_SCE_JMPREL = 0x61000029;
        public const uint DT_SCE_PLTREL = 0x6100002B;
        public const uint DT_SCE_PLTRELSZ = 0x6100002D;
        public const uint DT_SCE_RELA = 0x6100002F;
        public const uint DT_SCE_RELASZ = 0x61000031;
        public const uint DT_SCE_RELAENT = 0x61000033;
        public const uint DT_SCE_STRTAB = 0x61000035;
        public const uint DT_SCE_STRSZ = 0x61000037;
        public const uint DT_SCE_SYMTAB = 0x61000039;
        public const uint DT_SCE_SYMENT = 0x6100003B;
        public const uint DT_SCE_HASHSZ = 0x6100003D;
        public const uint DT_SCE_SYMTABSZ = 0x6100003F;

        public const uint SHT_SCE_NID = 0x61000001;
        public const uint SHT_SCE_IDK = 0x09010102;

        public const uint EF_ORBIS_FUNCTION_DATA_SECTIONS = 0x04000000;

        public const int R_X86_64_ORBIS_GOTPCREL_LOAD = 40; // RELOC_NUMBER(R_X86_64_ORBIS_GOTPCREL_LOAD, 40)

    }
    internal class Elf
    {
        internal class Elf64_Addr
        {
            public ulong Value { get; set; }
            public static implicit operator Elf64_Addr(ulong value) => new Elf64_Addr { Value = value };
            public static implicit operator ulong(Elf64_Addr value) => value.Value;
        }

        internal class Elf64_Off
        {
            public ulong Value { get; set; }
            public static implicit operator Elf64_Off(ulong value) => new Elf64_Off { Value = value };
            public static implicit operator ulong(Elf64_Off value) => value.Value;
            public static implicit operator int(Elf64_Off value) => (int)value.Value;
        }

        internal class Elf64_Offs
        {
            public ulong Value { get; set; }
            public static implicit operator Elf64_Offs(ulong value) => new Elf64_Offs { Value = value };
            public static implicit operator ulong(Elf64_Offs value) => value.Value;
        }

        internal class Elf64_Half
        {
            public ushort Value { get; set; }
            public static implicit operator Elf64_Half(ushort value) => new Elf64_Half { Value = value };
            public static implicit operator ushort(Elf64_Half value) => value.Value;
        }

        internal class Elf64_SHalf
        {
            public short Value { get; set; }
            public static implicit operator Elf64_SHalf(short value) => new Elf64_SHalf { Value = value };
            public static implicit operator short(Elf64_SHalf value) => value.Value;
        }

        internal class Elf64_Word
        {
            public uint Value { get; set; }
            public static implicit operator Elf64_Word(uint value) => new Elf64_Word { Value = value };
            public static implicit operator uint(Elf64_Word value) => value.Value;
        }

        internal class Elf64_Sword
        {
            public int Value { get; set; }
            public static implicit operator Elf64_Sword(int value) => new Elf64_Sword { Value = value };
            public static implicit operator int(Elf64_Sword value) => value.Value;
        }

        internal class Elf64_Xword
        {
            public ulong Value { get; set; }
            public static implicit operator Elf64_Xword(ulong value) => new Elf64_Xword { Value = value };
            public static implicit operator ulong(Elf64_Xword value) => value.Value;
            public static implicit operator int(Elf64_Xword value) => (int)value.Value;
            public static implicit operator uint(Elf64_Xword value) => (uint)value.Value;
        }

        internal class Elf64_Sxword
        {
            public long Value { get; set; }
            public static implicit operator Elf64_Sxword(long value) => new Elf64_Sxword { Value = value };
            public static implicit operator long(Elf64_Sxword value) => value.Value;
        }

        /* These constants are for the segment types stored in the image headers */
        public const int PT_NULL = 0;
        public const int PT_LOAD = 1;
        public const int PT_DYNAMIC = 2;
        public const int PT_INTERP = 3;
        public const int PT_NOTE = 4;
        public const int PT_SHLIB = 5;
        public const int PT_PHDR = 6;
        public const int PT_TLS = 7;               /* Thread local storage segment */
        public const int PT_LOOS = 0x60000000;      /* OS-specific */
        public const int PT_HIOS = 0x6fffffff;      /* OS-specific */
        public const int PT_LOPROC = 0x70000000;
        public const int PT_HIPROC = 0x7fffffff;

        public const int EM_X86_64 = 62;    /* AMD x86-64 */

        public const int EI_NIDENT = 16;

        [StructLayout(LayoutKind.Sequential)]
        internal class Elf64_Ehdr
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = EI_NIDENT)]
            public byte[] e_ident = new byte[EI_NIDENT];    /* ELF "magic number" */
            public Elf64_Half e_type;
            public Elf64_Half e_machine;
            public Elf64_Word e_version;
            public Elf64_Addr e_entry;    /* Entry point virtual address */
            public Elf64_Off e_phoff;    /* Program header table file offset */
            public Elf64_Off e_shoff;    /* Section header table file offset */
            public Elf64_Word e_flags;
            public Elf64_Half e_ehsize;
            public Elf64_Half e_phentsize;
            public Elf64_Half e_phnum;
            public Elf64_Half e_shentsize;
            public Elf64_Half e_shnum;
            public Elf64_Half e_shstrndx;

            public Elf64_Ehdr(Span<byte> span)
            {
                e_ident = span.Slice(0, EI_NIDENT).ToArray();
                e_type = BitConverter.ToUInt16(span.Slice(16, 2));
                e_machine = BitConverter.ToUInt16(span.Slice(18, 2));
                e_version = BitConverter.ToUInt32(span.Slice(20, 4));
                e_entry = BitConverter.ToUInt64(span.Slice(24, 8));
                e_phoff = BitConverter.ToUInt64(span.Slice(32, 8));
                e_shoff = BitConverter.ToUInt64(span.Slice(40, 8));
                e_flags = BitConverter.ToUInt32(span.Slice(48, 4));
                e_ehsize = BitConverter.ToUInt16(span.Slice(52, 2));
                e_phentsize = BitConverter.ToUInt16(span.Slice(54, 2));
                e_phnum = BitConverter.ToUInt16(span.Slice(56, 2));
                e_shentsize = BitConverter.ToUInt16(span.Slice(58, 2));
                e_shnum = BitConverter.ToUInt16(span.Slice(60, 2));
                e_shstrndx = BitConverter.ToUInt16(span.Slice(62, 2));
            }
        }

        internal class Elf64_Phdr
        {
            public Elf64_Word p_type;
            public Elf64_Word p_flags;
            public Elf64_Off p_offset;    /* Segment file offset */
            public Elf64_Addr p_vaddr;    /* Segment virtual address */
            public Elf64_Addr p_paddr;    /* Segment physical address */
            public Elf64_Xword p_filesz;    /* Segment size in file */
            public Elf64_Xword p_memsz;    /* Segment size in memory */
            public Elf64_Xword p_align;    /* Segment alignment, file & memory */

            public Elf64_Phdr(Span<byte> span)
            {
                p_type = BitConverter.ToUInt32(span.Slice(0, 4));
                p_flags = BitConverter.ToUInt32(span.Slice(4, 4));
                p_offset = BitConverter.ToUInt64(span.Slice(8, 8));
                p_vaddr = BitConverter.ToUInt64(span.Slice(16, 8));
                p_paddr = BitConverter.ToUInt64(span.Slice(24, 8));
                p_filesz = BitConverter.ToUInt64(span.Slice(32, 8));
                p_memsz = BitConverter.ToUInt64(span.Slice(40, 8));
                p_align = BitConverter.ToUInt64(span.Slice(48, 8));
            }
        }

        public const byte EI_MAG0 = 0;    /* e_ident[] indexes */
        public const byte EI_MAG1 = 1;
        public const byte EI_MAG2 = 2;
        public const byte EI_MAG3 = 3;
        public const byte EI_CLASS = 4;
        public const byte EI_DATA = 5;
        public const byte EI_VERSION = 6;
        public const byte EI_OSABI = 7;
        public const byte EI_ABIVER = 8;
        public const byte EI_PAD = 9;

        public const byte ELFCLASSNONE = 0;    /* EI_CLASS */
        public const byte ELFCLASS32 = 1;
        public const byte ELFCLASS64 = 2;
        public const byte ELFCLASSNUM = 3;

        public const byte ELFDATANONE = 0;    /* e_ident[EI_DATA] */
        public const byte ELFDATA2LSB = 1;
        public const byte ELFDATA2MSB = 2;

        public const byte EV_NONE = 0;    /* e_version, EI_VERSION */
        public const byte EV_CURRENT = 1;
        public const byte EV_NUM = 2;

        public const byte ELFOSABI_NONE = 0;
        public const byte ELFOSABI_LINUX = 3;
        public const byte ELFOSABI_FREEBSD = 9;  /* e_ident[IE_OSABI] */

        public const byte ELF_OSABI = ELFOSABI_FREEBSD;


    }

}

