rule rumms_axml : banker
{
  meta:
    description = "RuMMSV2"
    ref = "https://www.zscaler.com/blogs/research/rumms-malware-back-enhancements"

  strings:
    $BIND_ACCESSIBILITY_SERVICE = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    $AccessibilityService = "android.accessibilityservice.AccessibilityService"
    $SEND_SMS = "SEND_SMS"
    $WRITE_SMS = "WRITE_SMS"
    $CALL_PHONE = "CALL_PHONE"
    $RECEIVE_SMS = "RECEIVE_SMS"
    $READ_CONTACTS = "READ_CONTACTS"
    $READ_SMS = "READ_SMS"

  condition:
    all of them
}

rule rumms_dex : banker
{
  meta:
    description = "RuMMSV2"
    md5 = "c1f80e88a0470711cac720a66747665e"
    ref = "https://www.zscaler.com/blogs/research/rumms-malware-back-enhancements"

  strings:
    // подтвердить
    $a = {
        D0 BF D0 BE D0 B4 D1 82 D0 B2 D0 B5 D1 80 D0 B4 D0 B8 D1 82 D1 8C
    }
    $b = "Characteristic"
    $c = "Correspond"
    $e = "разрешить"
    $f = "android.settings.ACCESSIBILITY_SETTINGS"
    $h = {
        12 04          //               const/4                 v4, 0x0
        13 00 09 00    //               const/16                v0, 0x0009
        23 00 68 00    //               new-array               v0, v0, [String
        1A 01 11 01    //               const-string            v1, "ok"
        4D 01 00 04    //               aput-object             v1, v0, v4
        12 11          //               const/4                 v1, 0x1
        1A 02 5F 01    //               const-string            v2, "yes"
        4D 02 00 01    //               aput-object             v2, v0, v1
        12 21          //               const/4                 v1, 0x2
        1A 02 CC 00    //               const-string            v2, "delete"
    }

  condition:
    all of them
}

