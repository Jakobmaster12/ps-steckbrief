# Steckbrief: 0f083aac77fb734a8e81fb9dff218f0414ac6c4c9a23b2832837fbc2c7e2031d.ps1

- SHA256: `0f083aac77fb734a8e81fb9dff218f0414ac6c4c9a23b2832837fbc2c7e2031d`
- Groesse: 146218 Bytes, 5864 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 561 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - ` n d 2 l l e
$nCM+$Pp7PFt
}
function kYrk
{
$nM3Yc=tBUWr M t I v x t o
$znW7Q9=tBUzE t f a
$ipk=pfYCv j g 5 7 H f k 1 k `
  - ` y u f V H
$tTqy=ekfMft 0 p R I i a 8 h 2 D L 1 +
$nqRSj=tBUzE K 6 c
$QInrZ=CKeZ 0 0 P F v i X c E G x F e 3 6
$u1W8hJ=f`
  - `
$xXBBQ=TvKCsX d l d U 9 `
  - ` 3 U e 7 j J 2 Y
$FRPlh=pfYCv f r p H t n G U t x `
  - ` E 8
$IBDs9S=dYce r 7 3 9 f W f i C
$HWvXu=ybLJ Q m b c c 4 5 r D Y H
$AJkbhA=dYce 3 L z w G Z d m c
$sDlO1b=hEhs f D X `
  - ` d i s
$i0FQ=TvKCsX o d k s E `
  - ` X Y D d m k d s
$sB9AJ=MNutd B s G v f D F W g t
$nWyAU=AjfxOT 2 5 y S 4
$wDSK=DyLqAf g 3 x O T v 8 y 3 O v a
$rpQeDp=T`
  - ` 3 2 e l d l l
$eJhlw6=yyKlK n e r k
$eJhlw6+$tNXZ
}
function OAZm
{
$XnBCE=YUnBl j C B o b P P L S A l
$v5R2pp=HHUJRB t`
  - ` D
$mMNK7x=CYjW G K j Y h a X `
  - ` T p 4 E
$aWzqG=pfYCv X o L k x 4 H o j Z p r w
$db2=ybLJ 2 u 4 t o C P b 4 c 3
$JhR58=DfPLk e Z 1 C Q m O / e E a A w /`
  - ` F p s B W
$tJMlLS=DyLqAf c d 3 G g F V K g K n T
$arvmKI=EbElM 8 J `
  - ` I e K L A q w e L j k C o
$eYm=qGVZ G l S 4 1 + h u E j 0
$fJape4=BEHT w q Y
$oNdq9h=GXpVy o n n 7 R R c F
$mqR=RcfxkK `
  - ` B r c
$tC0e3b=XpAzG k m u V w W M n
$xaCx+$arvmKI+$rmLj+$h3dE+$mqR+$hUq+$oNdq9h+$Ceui+$yUPL+$tJMlLS+$ilFm+$aWzqG+$tC0e3`
  - ` h i e K H D
$Yu3Kw=BOywO B N 7 p t V f C 2
$O6z=jlsEJc C q 3 C C n f 7 n S T M
$EJ6X=hEhs `
  - ` r p R 1 s
$Zrg8h=BOywO X m O c Z a 4 b N
$FiRRr=Yxux `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 1
  - reflection_assembly: 5
- Cmdlets: New-Object, Out-Null, Set-StrictMode, Where-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
