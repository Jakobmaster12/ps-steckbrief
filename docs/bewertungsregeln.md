# Bewertungsregeln (Entwurf)

Stand: 2026-11-16. Dieser Entwurf legt fest, wie Referenzannotationen entstehen
und wie Modellaussagen von Hand bewertet werden. Er wird nach dem Pilot
überarbeitet und danach nicht mehr geändert.

## 1. Referenzannotation

Die Referenz ist der Maßstab. Sie entsteht **von Hand, aus dem vollständigen
Skript, vor den Modellläufen**, und sie ist unabhängig vom Extraktor. Ein Fehler
des Extraktors darf nicht zum Maßstab werden.

Vorgehen je Fall:

1. Skript in der VM vollständig lesen. Kodierte Teile von Hand oder mit einem
   unabhängigen Werkzeug dekodieren (zum Beispiel CyberChef), nicht mit dem
   eigenen Extraktor. Erst danach mit dem Steckbrief vergleichen.
2. `annotationen/VORLAGE.json` kopieren, Datei nach der Fall-ID benennen
   (`<id>.json`, die ID steht in `faelle.csv`).
3. Jeden wichtigen Befund als einen Satz festhalten: Was sieht der Code vor?
   Dazu die Belegstelle. Richtwert: 3 bis 8 Befunde je Fall.
4. Alle IOCs eintragen, die das Skript wirklich verwendet. URLs aus
   Kommentaren oder Hilfetexten sind keine IOCs.
5. Weicht der Steckbrief von der eigenen Lesung ab, wird das in `bemerkung`
   notiert. Die Referenz wird dadurch nicht angepasst, außer die eigene Lesung
   war nachweislich falsch.

Ein Befund ist "wichtig", wenn er für die Einstufung oder für die Reaktion im
Incident Response gebraucht wird (Download, Ausführung, Persistenz, Abschalten
von Schutz, Datenabfluss). Ein gesetzter Fenstertitel ist es nicht.

## 2. Bewertung einer Modellaussage

Jede Zeile in `aussagen.csv` bekommt genau eine Bewertung. Maßgeblich ist das
Material, das das Modell in dieser Eingabe gesehen hat (A, B oder C).

| Bewertung | Bedeutung |
|---|---|
| `belegt` | Die Aussage stimmt und lässt sich am gezeigten Material nachvollziehen. |
| `richtig_unbelegt` | Die Aussage stimmt laut Referenz, aber das gezeigte Material belegt sie nicht. |
| `unbelegt` | Weder das Material noch die Referenz stützen die Aussage. Kandidat für Halluzination. |
| `falsch` | Die Aussage widerspricht dem Skript. |

Regeln für Grenzfälle:

- **Vorgesehen statt passiert.** Statisch lässt sich nur sagen, was der Code
  vorsieht. "Das Skript lädt eine Datei von X" gilt als "sieht vor". "Das
  Skript hat erfolgreich heruntergeladen" oder "die Verbindung wurde
  aufgebaut" ist `unbelegt`.
- **Liste ist kein Beleg für Verwendung.** Steht eine URL nur in einer
  Fundliste oder in einem Kommentar, belegt das keine Verbindung.
- **Selbst dekodiert.** Nennt das Modell bei Eingabe A einen Inhalt, den es
  selbst dekodiert haben muss, zählt er als `belegt`, wenn er exakt mit der
  Referenz übereinstimmt. Weicht er ab, ist er `falsch`.
- **Zu allgemein.** Aussagen ohne prüfbaren Inhalt ("das Skript ist
  verdächtig") werden nicht bewertet (Feld leer lassen).
- **Zusammengesetzte Aussagen.** Enthält eine Aussage zwei Behauptungen und
  nur eine stimmt, zählt die schlechtere Bewertung.
- Die Spalte `beleg_im_material` ist nur ein Hilfsmittel. Ein wörtliches Zitat
  macht eine falsche Schlussfolgerung nicht richtig.

In `referenz_befund` kommt die ID des Referenzbefunds (zum Beispiel `B2`), den
die Aussage trifft. Leer, wenn sie keinen trifft. Daraus errechnet
`evaluate.py`, wie viele Referenzbefunde ein Modell gefunden hat.

## 3. Zwei Zahlen gehören zusammen

Berichtet werden immer beide:

- **Gefundene Referenzbefunde** (wie viel vom Wichtigen erkennt das Modell?)
- **Anteil unbelegter und falscher Aussagen** (wie viel erfindet es?)

Ein Modell, das nur einen sicheren Befund nennt, hat wenige Fehler und
übersieht trotzdem fast alles.

## 4. Durchgespieltes Beispiel

Referenz: `annotationen/BEISPIEL_demo.json` (Demo-Skript der Oberfläche).

| Modellaussage | Eingabe | Bewertung | Warum |
|---|---|---|---|
| "Das Skript entpackt einen gzip-Block und führt ihn per IEX aus." | A | `belegt`, B2 | Steht im Rohcode, auch wenn IEX zerteilt ist. |
| "Der entpackte Befehl lädt stage2.ps1 von 192.0.2.10." | B | `belegt`, B3 | Steht in Schicht S1 des Steckbriefs. |
| "Der entpackte Befehl lädt stage2.ps1 von 192.0.2.10." | A | `belegt`, B3 | Selbst dekodiert und exakt richtig. |
| "Der entpackte Befehl lädt update.exe von 192.0.2.10." | A | `falsch` | Selbst dekodiert, aber Inhalt erfunden. |
| "Das Skript verbindet sich mit example.org." | B oder C | `unbelegt` | Die URL steht nur im Kommentar. |
| "Das Skript hat sich im Autostart eingetragen." | C | `unbelegt` | Ob es ausgeführt wurde, ist nicht bekannt. Richtig wäre "sieht vor". |
| "Das Skript deaktiviert den Defender." | C | `unbelegt` | Kommt nirgends vor. |

## 5. Offene Punkte für den Pilot

- Zeit je bewerteter Antwort messen. Daraus folgt die Zahl der Detailfälle.
- Zehn Antworten nach einer Woche ein zweites Mal bewerten und vergleichen
  (Übereinstimmung mit sich selbst). Wenn möglich bewertet eine zweite Person
  dieselben zehn.
- Prüfen, ob die vier Bewertungen reichen oder ob "teilweise richtig" fehlt.
