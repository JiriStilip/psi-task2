# 2. úloha z předmětu KIV/PSI - Topologie sítě

## Popis
Aplikace nejprve pomocí Scapy zjistí adresu výchozí brány. 
Následně z jednotlivých směrovačů v síti získává informace pomocí PySNMP, pokud je to možné. Uživateli jsou vypisovány vlastní adresy daného směrovače a nově nalezené dostupné sítě. 
Nejsou-li dostupné žádné další přeskoky, program končí. 

## Spuštění
Aplikace je spouštěna příkazem `python3 ./topology.py` volaným v kořenovém adresáři.
