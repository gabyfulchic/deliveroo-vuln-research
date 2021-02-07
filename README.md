# Tentative de reconnaissance de Deliveroo  
  
## Périmètre  
| Domaines                                            | Cadre                     | Autorisations                                                         | Interdictions                                                             |
|-----------------------------------------------------|---------------------------|-----------------------------------------------------------------------|---------------------------------------------------------------------------|
| `deliveroo.com` `deliveroo.com/*` `*.deliveroo.com` | Elective Pentest Ynov BDX | **Scanner**, **observer**, **identifier**, **relever** et **rédiger** | **Nuire** ou **affecter** les services et **publier** des données/failles |
  
## Reconnaissance DNS  
J'ai décidé d'utiliser différents outils afin de tous les tester, de me faire mon propre avis, et d'avoir plusieurs sources. Je vais aussi concaténer les résultats afin de sortir les valeurs uniques et avoir une liste franche des sous domaines pour ensuite procéder à la recherche des fichiers/sous-dossiers vulnérables sur les différents sous-domaines.   
  
### [Sublist3r](https://github.com/aboul3la/Sublist3r)  
```bash
py sublist3r.py -d deliveroo.com -o results/sublist3r.txt
```
[Result](results/sublist3r.txt)  
### [Amass-passive](https://github.com/OWASP/Amass)  
```bash
docker run -v /tmp:/tmp caffix/amass enum --passive -w /wordlists/all.txt -d deliveroo.com -o /tmp/amass.txt
mv /tmp/amass.txt results/amass.txt
```
[Result-passive](results/amass.txt)  
### [Amass-active](https://github.com/OWASP/Amass)  
```bash
docker run -v /tmp:/tmp caffix/amass enum -brute -w /wordlists/all.txt -d deliveroo.com -o /tmp/amass-brute-2hours.txt
mv /tmp/amass-brute-2hours.txt results/amass-brute-2hours.txt
```
[Result-active](results/amass-brute-2hours.txt)  
### [AssetFinder](https://github.com/tomnomnom/assetfinder)  
```bash
assetfinder deliveroo.com > results/assetfinder.txt  
cat results/assetfinder.txt | grep -v "deliveroo" | wc -l
683 # résultat très étrange, assetfinder trouve des sous-domaines aucun rapport avec deliveroo.com.
```
[Result](results/assetfinder.txt)  
### [SubFinder](https://github.com/projectdiscovery/subfinder)
```bash
./subfinder -d deliveroo.com -o results/subfinder.txt
```
[Result](results/subfinder.txt)
### [GoBuster](https://github.com/OJ/gobuster)
```bash
git clone https://github.com/danielmiessler/SecLists.git
gobuster dns -d deliveroo.com -w SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o results/gobuster.txt
```
[Result](results/gobuster.txt)  
### Total
* 231 sous-domaines trouvés uniques après concaténation et éloignement de résultats ambigus.  
```bash
cat results/amass.txt results/assetfinder.txt results/subfinder.txt results/sublist3r.txt | grep "deliveroo" | sort -u > results/total.txt
cat results/amass.txt results/assetfinder.txt results/subfinder.txt results/sublist3r.txt | grep "deliveroo" | sort -u | wc -l           
231
```
[Résultats-uniques](results/total.txt)
### [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)
```bash
cat deliveroo/results/total.txt | ./shuffledns -r massdns/lists/resolvers.txt -o deliveroo/results/shuffledns-over-total.txt
```
[Result](results/shuffledns-over-total.txt)
  
Après ces recherche de reconnaissance autour des sous-domaines à `deliveroo.com`, je me rends compte qu'il y a de tout. Il y a des sous-domaines qui existent car les records DNS trainent encore, mais il y a plusieurs sous-domaines qui me donnent envie d'investiguer car ce sont des noms de services connus ou des noms qui me parlent.  
  
Il y aussi eu quelques domaines/sous-domaines qui sont sortis de [assetfinder](https://github.com/tomnomnom/assetfinder) qui n'avaient aucun rapport avec `deliveroo.com` car ils se trouvaient certainement dans des liens ou étaient mentionnés quelque part dans les sous-domaines.  
  
- ldap.deliveroo.com (**52.174.159.35**)
```bash
ping ldap.deliveroo.com      

PING ldap.deliveroo.com (52.174.159.35) 56(84) bytes of data.
--- ldap.deliveroo.com ping statistics ---
12 packets transmitted, 0 received, 100% packet loss, time 272ms
```
- www.ad.corp.deliveroo.com (ancien URL de l'AD j'imagine)
```bash
ping www.ad.corp.deliveroo.com

ping: www.ad.corp.deliveroo.com: Name or service not known
```
- ad.corp.deliveroo.com (**54.154.61.155**)
```bash
ping ad.corp.deliveroo.com                                                      2 ↵

PING it-produc-rdgatewa-9379ba0echib-872471689.eu-west-1.elb.amazonaws.com (54.154.61.155) 56(84) bytes of data.
--- it-produc-rdgatewa-9379ba0echib-872471689.eu-west-1.elb.amazonaws.com ping statistics ---
8 packets transmitted, 0 received, 100% packet loss, time 183ms
```
- view.b2b.deliveroo.com (**161.71.61.128**)
```bash
ping view.b2b.deliveroo.com                                                     1 ↵

PING view.b2b.deliveroo.com (161.71.61.128) 56(84) bytes of data.
64 bytes from view.b2b.deliveroo.com (161.71.61.128): icmp_seq=1 ttl=242 time=31.3 ms
64 bytes from view.b2b.deliveroo.com (161.71.61.128): icmp_seq=2 ttl=242 time=31.5 ms
64 bytes from view.b2b.deliveroo.com (161.71.61.128): icmp_seq=3 ttl=242 time=32.8 ms
64 bytes from view.b2b.deliveroo.com (161.71.61.128): icmp_seq=4 ttl=242 time=32.9 ms
64 bytes from view.b2b.deliveroo.com (161.71.61.128): icmp_seq=5 ttl=242 time=32.7 ms
--- view.b2b.deliveroo.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 10ms
rtt min/avg/max/mdev = 31.345/32.232/32.859/0.688 ms
```
- click.b2b.deliveroo.com (**161.71.59.130**)
```bash
ping click.b2b.deliveroo.com

PING click.b2b.deliveroo.com (161.71.59.130) 56(84) bytes of data.
64 bytes from click.b2b.deliveroo.com (161.71.59.130): icmp_seq=1 ttl=242 time=30.9 ms
64 bytes from click.b2b.deliveroo.com (161.71.59.130): icmp_seq=2 ttl=242 time=32.5 ms
64 bytes from click.b2b.deliveroo.com (161.71.59.130): icmp_seq=3 ttl=242 time=32.7 ms
64 bytes from click.b2b.deliveroo.com (161.71.59.130): icmp_seq=4 ttl=242 time=32.5 ms
64 bytes from click.b2b.deliveroo.com (161.71.59.130): icmp_seq=5 ttl=242 time=32.7 ms
--- click.b2b.deliveroo.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 11ms
rtt min/avg/max/mdev = 30.921/32.270/32.715/0.679 ms
```
- cloud.b2b.deliveroo.com (**161.71.80.32**)
```bash
ping cloud.b2b.deliveroo.com

PING cloud.b2b.deliveroo.com (161.71.80.32) 56(84) bytes of data.
64 bytes from cloud.b2b.deliveroo.com (161.71.80.32): icmp_seq=1 ttl=241 time=31.5 ms
64 bytes from cloud.b2b.deliveroo.com (161.71.80.32): icmp_seq=2 ttl=241 time=33.1 ms
64 bytes from cloud.b2b.deliveroo.com (161.71.80.32): icmp_seq=3 ttl=241 time=34.1 ms
64 bytes from cloud.b2b.deliveroo.com (161.71.80.32): icmp_seq=4 ttl=241 time=32.9 ms
64 bytes from cloud.b2b.deliveroo.com (161.71.80.32): icmp_seq=5 ttl=241 time=32.6 ms
--- cloud.b2b.deliveroo.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 9ms
rtt min/avg/max/mdev = 31.532/32.834/34.064/0.828 ms
```
- J'ai listé les 5 IPs dans un fichier texte histoire d'automatiser d'autres recherches.
```bash
cat results/ips.txt
52.174.159.35
54.154.61.155
161.71.61.128
161.71.59.130
161.71.80.32
```

## Reconnaissance Réseaux
### [Massdns pour avoir des infos sur les records derrière les sous-domaines.](https://github.com/blechschmidt/massdns)
```bash
git clone https://github.com/blechschmidt/massdns
cd massdns/
make
./bin/massdns -r lists/resolvers.txt -t A ../deliveroo/results/total.txt > ../deliveroo/results/massdns-over-total.txt
```
### **Nmap** fast scan (100 most common ports)
```bash
while IFS= read -r subdomain; do nmap -F $subdomain >> results/nmap-fast-scan.txt; done < results/ips.txt 
```
### **Nmap** full scan
```bash
while IFS= read -r subdomain; do nmap -p- $subdomain >> results/nmap-full-scan.txt; done < results/ips.txt
```
### [GoSpider](https://github.com/jaeles-project/gospider)
```bash
gospider -v --js --sitemap --robots --site "http://deliveroo.com" -o deliveroo/results/gospider
gospider -v --site "http://deliveroo.com" -o deliveroo/results/gospider
```
[Result](results/gospider)
### [OpenNikto](https://github.com/sullo/nikto)
```bash
git clone https://github.com/sullo/nikto.git
cd nikto
docker build -t sullo/nikto .
docker run --rm -v /tmp:/tmp sullo/nikto -h http://deliveroo.com -o /tmp/nikto.json
mv /tmp/nikto.json results/nikto.json
```
[Result](results/nikto.json)
