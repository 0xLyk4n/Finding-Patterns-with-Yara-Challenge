rule pe32
{
   meta:
    name = "Subho"
    desc = "pe"
  strings:
    $hex_string1 = { 50 45 00 00 4C }
    $hex_string2 = { 50 45 00 00 64 86 }
  condition:
    $hex_string1 or $hex_string2 at 0
}
