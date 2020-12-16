// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt
rule APT_Backdoor_MSIL_SUNBURST_3
{
    meta:
        author = "FireEye"
        description = "This rule is looking for certain portions of the SUNBURST backdoor that deal with C2 communications. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
    strings:
        $sb1 = { 05 14 51 1? 0A 04 28 [2] 00 06 0? [0-16] 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F ?? 2E ?? 03 1F [1-32] 03 0? 05 28 [2] 00 06 0? [0-32] 03 [0-16] 59 45 06 }
        $sb2 = { FE 16 [2] 00 01 6F [2] 00 0A 1? 8D [2] 00 01 [0-32] 1? 1? 7B 9? [0-16] 1? 1? 7D 9? [0-16] 6F [2] 00 0A 28 [2] 00 0A 28 [2] 00 0A [0-32] 02 7B [2] 00 04 1? 6F [2] 00 0A [2-32] 02 7B [2] 00 04 20 [4] 6F [2] 00 0A [0-32] 13 ?? 11 ?? 11 ?? 6E 58 13 ?? 11 ?? 11 ?? 9? 1? [0-32] 60 13 ?? 0? 11 ?? 28 [4] 11 ?? 11 ?? 9? 28 [4] 28 [4-32] 9? 58 [0-32] 6? 5F 13 ?? 02 7B [2] 00 04 1? ?? 1? ?? 6F [2] 00 0A 8D [2] 00 01 }
        $ss1 = "\x00set_UseShellExecute\x00"
        $ss2 = "\x00ProcessStartInfo\x00"
        $ss3 = "\x00GetResponseStream\x00"
        $ss4 = "\x00HttpWebResponse\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}