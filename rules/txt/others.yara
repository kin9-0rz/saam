
rule jack_3x : system
{
  meta:
    description = "system path"

  strings:
    $system_bin = "/system/"

  condition:
    $system_bin
}

rule runtime_exec : shell
{
  meta:
    description = "system shell"

  strings:
    $system_bin = "java/lang/Runtime;->exec"

  condition:
    $system_bin
}

rule system_app : system
{
  meta:
    description = "system app"

  strings:
    $system_bin = "/system/app/"

  condition:
    $system_bin
}



rule zygote : zygote
{
  meta:
    description = "zygote"

  strings:
    $system_bin = "zygote"

  condition:
    $system_bin
}


rule reboot : system
{
  meta:
    description = "reboot"

  strings:
    $system_bin = "/system/bin/reboot"

  condition:
    $system_bin
}

rule root : system
{
  meta:
    description = "root"

  strings:
    $system_bin_su = "/system/bin/su"
    $system_xbin_su = "/system/xbin/su"
    $su = "\"su\""

  condition:
    any of them
}

rule owner_data : manifest
{
  meta:
    description = "owner_data"

  strings:
    $system_bin_su = "READ_OWNER_DATA"
    $system_xbin_su = "WRITE_OWNER_DATA"

  condition:
    any of them
}

rule disable_use_usb : usb
{
  meta:
    description = "disable use usb"
    doc = "setprop persist.sys.usb.config none"

  strings:
    $a = "persist.sys.usb.config"

  condition:
    any of them
}