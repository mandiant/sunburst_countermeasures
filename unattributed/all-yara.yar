// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/sunburst_countermeasures/blob/main/LICENSE.txt

rule APT_Webshell_MSIL_SUPERNOVA_1
{
    meta:
        author = "FireEye"
        description = "SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args). This rule is looking for specific strings and attributes related to SUPERNOVA."
    strings:
        $compile1 = "CompileAssemblyFromSource"
        $compile2 = "CreateCompiler"
        $context = "ProcessRequest"
        $httpmodule = "IHttpHandler" ascii
        $string1 = "clazz"
        $string2 = "//NetPerfMon//images//NoLogo.gif" wide
        $string3 = "SolarWinds" ascii nocase wide
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and pe.imports("mscoree.dll","_CorDllMain") and $httpmodule and $context and all of ($compile*) and all of ($string*)
}
rule APT_Webshell_MSIL_SUPERNOVA_2
{
    meta:
        author = "FireEye"
        description = "This rule is looking for specific strings related to SUPERNOVA. SUPERNOVA is a .NET web shell backdoor masquerading as a legitimate SolarWinds web service handler. SUPERNOVA inspects and responds to HTTP requests with the appropriate HTTP query strings, Cookies, and/or HTML form values (e.g. named codes, class, method, and args)."
    strings:
        $dynamic = "DynamicRun"
        $solar = "Solarwinds" nocase
        $string1 = "codes"
        $string2 = "clazz"
        $string3 = "method"
        $string4 = "args"
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize < 10KB and 3 of ($string*) and $dynamic and $solar
}
rule APT_HackTool_PS1_COSMICGALE_1
{
    meta:
        author = "FireEye"
        description = "This rule detects various unique strings related to COSMICGALE. COSMICGALE is a credential theft and reconnaissance PowerShell script that collects credentials using the publicly available Get-PassHashes routine. COSMICGALE clears log files, writes acquired data to a hard coded path, and encrypts the file with a password."
    strings:
        $sr1 = /\[byte\[\]\]@\([\x09\x20]{0,32}0xaa[\x09\x20]{0,32},[\x09\x20]{0,32}0xd3[\x09\x20]{0,32},[\x09\x20]{0,32}0xb4[\x09\x20]{0,32},[\x09\x20]{0,32}0x35[\x09\x20]{0,32},/ ascii nocase wide
        $sr2 = /\[bitconverter\]::toint32\(\$\w{1,64}\[0x0c..0x0f\][\x09\x20]{0,32},[\x09\x20]{0,32}0\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}0xcc\x3b/ ascii nocase wide
        $sr3 = /\[byte\[\]\]\(\$\w{1,64}\.padright\(\d{1,2}\)\.substring\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,2}\)\.tochararray\(\)\)/ ascii nocase wide
        $ss1 = "[text.encoding]::ascii.getbytes(\"ntpassword\x600\");" ascii nocase wide
        $ss2 = "system\\currentcontrolset\\control\\lsa\\$_" ascii nocase wide
        $ss3 = "[security.cryptography.md5]::create()" ascii nocase wide
        $ss4 = "[system.security.principal.windowsidentity]::getcurrent().name" ascii nocase wide
        $ss5 = "out-file" ascii nocase wide
        $ss6 = "convertto-securestring" ascii nocase wide
    condition:
        all of them
}