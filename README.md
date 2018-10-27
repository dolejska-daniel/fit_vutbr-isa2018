# ISA - Export DNS informací
> Cílem projektu je vytvořit aplikaci, která bude umět zpracovávat data protokolu DNS (Domain Name System) a vybrané statistiky exportovat pomocí protokolu Syslog na centrální logovací server.
 

## Omezení projektu

Spolehlivě zpracovává pouze `IPv4` komunikaci používající protokol `UDP`. Protokol `TCP` není plně podporován.


## Práce s programem

### Překlad programu

Pro překlad programu je použit CMake. K projektu je připojen i výchozí `Makefile`
(vygenerovaný za pomoci CMake) - pro překlad tedy stačí jednoduchý příkaz `make`
popřípadě pak `cmake ./ && cmake --build ./`.


### Spuštění programu

Pro správné spuštění program vyžaduje alespoň přepínač `-r` nebo `-i`, k dispozici jsou následující přepínače:

| Přepínač         | Argument                         | Význam
|------------------|----------------------------------|--------
| `-r <filepath>`  | Cesta k `pcap` souboru.          | _Nepovinný._ Specifikuje cestu k souboru, který bude aplikace zpracovávat. **Nelze použít s přepínačem `-i`.**
| `-i <interface>` | Identifikátor síťového rozhraní. | _Nepovinný._ Specifikuje identifikátor síťového rozhraní, na kterém bude program odchytávat síťový provoz*. **Nelze použít s přepínačem `-r`.**
| `-s <address>`   | Adresa syslog serveru.           | _Nepovinný._ Specifikuje adresu (IPv4/IPv6) nebo hostname syslog serveru, na který se budou statistiky odesílat**. 
| `-t <interval>`  | Časový interval v sekundách.     | _Nepovinný, výchozí hodnota `60`._ Specifikuje časový interval, pro který se budou statistiky vypočítávat***. 

*Použití socketů typu `SOCK_RAW` v implementaci vyžaduje při spuštění oprávnění **superusera**.

**Pokud není použit jsou statistiky vypsány na standardní výstup (forma viz kapitola [Výstup](#vystup)).

***Pokud není použit při použití přepínače `-r`, jsou statistiky vypočteny pro celý soubor. Jinak jsou použity časové rozdíly mezi pakety.

_Další informace v MAN page `dns-export.1`._

### Běh programu

Kdykoliv za běhu programu je možné procesu odeslat signál `SIGUSR1`, který na standardní výstup vypíše statistiky provozu v rámci aktuálního časového intervalu.

```shell
sudo kill -s USR1 $(ps -aux | grep [d]ns-export | awk '{ print $2 }')
```

Tabulka statistik nebude vyprázdněna a na syslog server (v případě, že je odpovídajícím přepínačem specifikován) nebude nic odesláno.


### Výstup

**$TITLE**:
```
=== DNS Traffic Statistics (last %ld minute(s) %ld second(s)) ===
```

**$MESSAGE**:

Pro záznamy `A`, `AAAA`, `CNAME`, `NS` a `PTR` platí následující formát:
```php
$DOMAIN_NAME $RR_TYPE $RR_RDATA $COUNT
```
Pro ostatní pak:
```php
$DOMAIN_NAME $RR_TYPE "$RR_RDATA" $COUNT
```


#### Standardní výstup

Výpis statistik na standardní výstup probíhá na základě následujícího formátu
(čísla v závorkách reprezentují počet výskytů vrámci jedoho výpisu):

```php
$TITLE\n (1)
$MESSAGE\n (0-n)
\n (1)
```

K výpisu statistik dojde buď na konci časového intervalu pro agregaci statistik,
v případě dokončení zpracování `.pcap` souboru či při zaslání `SIGUSR1` signálu.

Program na `stdout` dále vypisuje jeden aktivní řádek, jehož obsah mění
v závislosti na posledním zpracovaném DNS záznamu. Před výpisem statistik jej
program automaticky maže. Řádek se řídí následujícím formátem:
```php
$MESSAGE +1
```


#### Formát syslog zprávy

Syslog zprávy se řídí následujícím formátem:

```php
<134> 1 YYYY-mm-ddTHH:ii:ss.000Z $HOSTNAME dns-export $PID - - $MESSAGE
```

Zprávy **nejsou** na syslog server odesílány jednotlivě -- jsou přidávány do bufferu do maximální délky 1024 znaků a jsou odeslány až po jeho naplnění. Jednotlivé zprávy jsou mezi sebou v rámci paketu odděleny pomocí CRLF (`0d 0a`).

