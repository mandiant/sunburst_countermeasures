rule solarwinds_sunburst_compromised_cert
{
meta:
    description = "Detects signing certificate serial used in trojanized SolarWinds .msp hotfix"
    hash = "d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600"
strings:
    $ = {0F E9 73 75 20 22 A6 06 AD F2 A3 6E 34 5D C0 ED}
condition:
    any of them
}
