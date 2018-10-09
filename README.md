# ISA - Export DNS informací
> Cílem projektu je vytvořit aplikaci, která bude umět zpracovávat data protokolu DNS (Domain Name System) a vybrané statistiky exportovat pomocí protokolu Syslog na centrální logovací server.
 

## Omezení projektu

Zpracovává pouze `IPv4` komunikaci používající protokol `UDP`.


## Práce s programem

### Překlad programu

_TBD_


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
```php
$DOMAIN_NAME $RR_TYPE $RR_RDATA $COUNT
```


#### Standardní výstup

Výpis statistik na standardní výstup probíhá na základě následujícího formátu:

```php
$TITLE\n (1)
$MESSAGE\n (0-n)
\n
```


#### Formát syslog zprávy

Syslog zprávy se řídí následujícím formátem:

```php
<134> 1 YYYY-mm-ddTHH:ii:ss.000Z $HOSTNAME dns-export $PID - - $MESSAGE
```

Zprávy **nejsou** na syslog server odesílány jednotlivě -- jsou přidávány do bufferu do maximální délky 1024 znaků a jsou odeslány až po jeho naplnění. Jednotlivé zprávy jsou mezi sebou v rámci paketu odděleny pomocí CRLF (`0d 0a`).

