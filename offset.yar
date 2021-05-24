rule offset
{
  meta:
    name = "Subho"
    desc = "offset"
  strings:
    $my_text_string = "cmd.exe /c \"%s\""
  condition:
    $my_text_string
}
