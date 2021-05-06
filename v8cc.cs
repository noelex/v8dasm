using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace v8cc
{
    // Set Pack = 4 for 32-bit V8
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    struct CodeCacheHeader
    {
        public uint MagicNumber { get; set; }
        public uint VersionHash { get; set; }
        public uint SourceHash { get; set; }
        public uint FlagHash { get; set; }
        public uint NumReservations { get; set; }
        public uint PayloadLength { get; set; }
        public uint Checksum { get; set; }
    }

    class Program
    {
        // The following constants are taken from V8 v8.7.220.25 source code.
        // You may need to modify them to match your specific version of V8.
        private const int kSystemPointerSizeLog2 = 3, // 2 for 32-bit V8 and 3 for 64-bit V8
            kPointerAlignment = 1 << kSystemPointerSizeLog2,
            kPointerAlignmentMask = kPointerAlignment - 1;

        private const uint kUInt32Size = 4;

        private const uint 
            kMagicNumberOffset = 0,
            kVersionHashOffset = kMagicNumberOffset + kUInt32Size,
            kSourceHashOffset = kVersionHashOffset + kUInt32Size,
            kFlagHashOffset = kSourceHashOffset + kUInt32Size,
            kNumReservationsOffset = kFlagHashOffset + kUInt32Size,
            kPayloadLengthOffset = kNumReservationsOffset + kUInt32Size,
            kChecksumOffset = kPayloadLengthOffset + kUInt32Size,
            kUnalignedHeaderSize = kChecksumOffset + kUInt32Size,
            kHeaderSize = (uint)((kUnalignedHeaderSize + kPointerAlignmentMask) & ~kPointerAlignmentMask);

        static void Main(string[] args)
        {
            var action = args[0];
            var file = args[1];

            switch (action)
            {
                case "validate":
                    ValidateChecksum(file);
                    break;
                case "rehash":
                    RewriteCheckSum(file);
                    break;
            }
        }

        private static void ValidateChecksum(string file)
        {
            var data = File.ReadAllBytes(file).AsSpan();
            var header = MemoryMarshal.Cast<byte, CodeCacheHeader>(data.Slice(0, (int)kHeaderSize))[0];
            var checksum=Checksum(ChecksummedContent(data));
            Console.WriteLine($"Magic:           0x{header.MagicNumber:X8}");
            Console.WriteLine($"VersionHash:     0x{header.VersionHash:X8}");
            Console.WriteLine($"SourceHash:      0x{header.SourceHash:X8}");
            Console.WriteLine($"FlagHash:        0x{header.FlagHash:X8}");
            Console.WriteLine($"NumReservations: 0x{header.NumReservations:X8}");
            Console.WriteLine($"PayloadLength:   0x{header.PayloadLength:X8}");
            Console.WriteLine($"Checksum:        0x{header.Checksum:X8}");
            Console.WriteLine($"Actual Checksum: 0x{checksum:X8}");

            Console.WriteLine();
            Console.WriteLine($"Result: {(checksum == header.Checksum ? "Match" : "Mismatch")}");
        }

        private static void RewriteCheckSum(string file)
        {
            var data = File.ReadAllBytes(file).AsSpan();
            var header =  MemoryMarshal.Cast<byte, CodeCacheHeader>(data.Slice(0, (int)kHeaderSize));
            header[0].Checksum = Checksum(ChecksummedContent(data));
            File.WriteAllBytes(file, buf);

            Console.WriteLine($"New checksum value 0x{header[0].Checksum:X8} written.");
        }

        private static ReadOnlySpan<byte> ChecksummedContent(ReadOnlySpan<byte> data)
            => data[(int)kHeaderSize..];

        private static uint Checksum(ReadOnlySpan<byte> data)
        {
            return Adler32(0, data);
        }

        // Adler-32 implementation ported from zlib.
        static uint Adler32(uint adler, ReadOnlySpan<byte> buf)
        {
            const uint BASE = 65521U;
            const int NMAX = 5552;
            uint sum2;

            void DO1(ReadOnlySpan<byte> buf, int i) { adler += buf[i]; sum2 += adler; }
            void DO2(ReadOnlySpan<byte> buf, int i) { DO1(buf, i); DO1(buf, i + 1); }
            void DO4(ReadOnlySpan<byte> buf, int i) { DO2(buf, i); DO2(buf, i + 2); }
            void DO8(ReadOnlySpan<byte> buf, int i) { DO4(buf, i); DO4(buf, i + 4); }
            void DO16(ReadOnlySpan<byte> buf) { DO8(buf, 0); DO8(buf, 8); }

            void MOD(ref uint a) => a %= BASE;
            void MOD28(ref uint a) => a %= BASE;

            int len = buf.Length;
            var p = 0;
            {
                uint n;

                /* split Adler-32 into component sums */
                sum2 = (adler >> 16) & 0xffff;
                adler &= 0xffff;

                /* in case user likes doing a byte at a time, keep it fast */
                if (len == 1)
                {
                    adler += buf[0];
                    if (adler >= BASE)
                        adler -= BASE;
                    sum2 += adler;
                    if (sum2 >= BASE)
                        sum2 -= BASE;
                    return adler | (sum2 << 16);
                }

                /* initial Adler-32 value (deferred check for len == 1 speed) */
                if (buf == default)
                    return 1;

                /* in case short lengths are provided, keep it somewhat fast */
                if (len < 16)
                {
                    while (len-- != 0)
                    {
                        adler += buf[p++];
                        sum2 += adler;
                    }
                    if (adler >= BASE)
                        adler -= BASE;
                    MOD28(ref sum2);            /* only added so many BASE's */
                    return adler | (sum2 << 16);
                }

                /* do length NMAX blocks -- requires just one modulo operation */
                while (len >= NMAX)
                {
                    len -= NMAX;
                    n = NMAX / 16;          /* NMAX is divisible by 16 */
                    do
                    {
                        DO16(buf.Slice(p));          /* 16 sums unrolled */
                        p += 16;
                    } while (--n != 0);
                    MOD(ref adler);
                    MOD(ref sum2);
                }

                /* do remaining bytes (less than NMAX, still just one modulo) */
                if (len != 0)
                {                  /* avoid modulos if none remaining */
                    while (len >= 16)
                    {
                        len -= 16;
                        DO16(buf.Slice(p));
                        p += 16;
                    }
                    while (len-- != 0)
                    {
                        adler += buf[p++];
                        sum2 += adler;
                    }
                    MOD(ref adler);
                    MOD(ref sum2);
                }

                /* return recombined sums */
                return adler | (sum2 << 16);
            }
        }
    }
}