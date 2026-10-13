# 🎯 DVWA Attack & Detection Lab

Lab offensif/défensif : des attaques web réelles (injection SQL, XSS, brute
force, injection de commandes) sont menées depuis Kali contre une application
volontairement vulnérable (DVWA) hébergée en DMZ, puis détectées par Suricata
et corrélées dans Wazuh. L'objectif est de documenter le cycle complet
**attaque → détection → analyse**, sur l'infrastructure pfSense déjà
segmentée du lab précédent.

➡️ Ce lab s'appuie sur [`pfsense-suricata-lab`](https://github.com/alexbzz/network-security-lab)
et [`wazuh-siem-lab`](https://github.com/alexbzz/wazuh-siem-lab), qui détaillent la mise en
place de la segmentation réseau, de Suricata et du SIEM.

## 🎯 Objectif

Déployer DVWA en DMZ, mener plusieurs classes d'attaques web depuis Kali,
vérifier leur détection par Suricata, suivre leur corrélation dans Wazuh, et
documenter chaque scénario avec son trafic, son alerte et son analyse.

## 🧰 Technologies

| Outil | Rôle |
|-------|------|
| DVWA | Application web volontairement vulnérable, cible des attaques |
| Kali Linux | Machine d'attaque (navigateur, sqlmap, hydra) |
| pfSense | Pare-feu / routeur, segmentation LAN / DMZ |
| Suricata | IDS, détection des attaques web |
| Wazuh | SIEM, corrélation et analyse des alertes |
| Debian | Serveur hébergeant DVWA (Apache, MariaDB, PHP) |
| VMware Workstation | Virtualisation |

## 🗺️ Architecture

```
            Internet
                |
             pfSense
                |
        -----------------
        |               |
       LAN             DMZ
        |               |
      Kali         Debian + DVWA
   (attaquant)      (cible vulnérable)
```

| Zone | Réseau | Machine | Rôle |
|------|--------|---------|------|
| LAN | 192.168.1.0/24 | Kali Linux | Attaquant |
| LAN | 192.168.1.0/24 | Serveur Wazuh | SIEM, corrélation |
| DMZ | 192.168.2.0/24 | Debian + DVWA | Cible vulnérable |

![Schéma réseau](screenshots/00-architecture.png)

## ⚙️ Mise en place

### 1. Installation de DVWA
Apache, MariaDB, PHP, DVWA cloné depuis GitHub, base de données initialisée.

![Installation DVWA](screenshots/01-dvwa-install.png)
![Page de login DVWA](screenshots/01b-dvwa-login.png)

### 2. Configuration du niveau de sécurité
Niveau réglé sur **Low** pour les premiers scénarios, avant de durcir
progressivement (Medium, High) pour comparer la détection.

![DVWA Security settings](screenshots/02-dvwa-security-level.png)

## 🎯 Scénarios d'attaque

### 3. Injection SQL
Extraction de données via une requête SQL manipulée dans le champ de
recherche utilisateur de DVWA.

![Attaque SQLi](screenshots/03-attack-sqli.png)
![Alerte Suricata SQLi](screenshots/03b-suricata-alert-sqli.png)
![Corrélation Wazuh SQLi](screenshots/03c-wazuh-sqli.png)
![Règle injection SQL](screenshots/03s-rules-pfsense-sqli.png)

### 4. Brute force
Attaque par dictionnaire sur le formulaire de connexion DVWA avec Hydra.

![Commande Hydra](screenshots/04-attack-bruteforce.png)
![Alerte Suricata brute force](screenshots/04b-suricata-alert-bruteforce.png)
![Corrélation Wazuh brute force](screenshots/04c-wazuh-bruteforce.png)

### 5. Cross-Site Scripting (XSS)
Injection d'un script dans un champ non filtré, exécuté côté client.

![Payload XSS](screenshots/05-attack-xss.png)
![Alerte Suricata XSS](screenshots/05b-suricata-alert-xss.png)
![Corrélation Wazuh XSS](screenshots/05c-wazuh-xss.png)

### 6. Injection de commandes
Exécution de commandes système via le module Command Injection de DVWA.

![Attaque Command Injection](screenshots/06-attack-command-injection.png)
![Alerte Suricata Command Injection](screenshots/06b-suricata-alert-cmdi.png)
![Corrélation Wazuh Command Injection](screenshots/06c-wazuh-cmdi.png)

## 🔬 Comparaison par niveau de sécurité

Même attaque (SQLi) rejouée sur les trois niveaux DVWA, pour illustrer
l'effet des protections applicatives sur la détection réseau.

| Niveau | Attaque réussie | Détectée par Suricata |
|--------|------------------|------------------------|
| Low | ⬜ | ⬜ |
| Medium | ⬜ | ⬜ |
| High | ⬜ | ⬜ |

![Comparaison des niveaux](screenshots/07-security-levels-comparison.png)

## ✅ Tests et résultats

| Test | Attendu | Résultat |
|------|---------|----------|
| SQL Injection détectée | Alerte Suricata + Wazuh | ⬜ |
| Brute force détecté | Alerte Suricata + Wazuh | ⬜ |
| XSS détecté | Alerte Suricata + Wazuh | ⬜ |
| Command Injection détectée | Alerte Suricata + Wazuh | ⬜ |
| Corrélation complète dans Wazuh | Source, IP attaquante, signature visibles | ⬜ |

## 🧩 Difficultés rencontrées

*(à compléter au fil du lab)*

## 📚 Ce que j'ai appris

- Mise en œuvre d'attaques web classiques (OWASP Top 10) en environnement
  contrôlé
- Détection réseau d'attaques applicatives avec Suricata
- Corrélation d'alertes multi-sources dans un SIEM
- Effet du durcissement applicatif sur la détectabilité d'une attaque

## 🚀 Pistes d'amélioration

- Automatiser les scénarios avec des scripts (reproductibilité)
- Ajouter des règles Suricata personnalisées pour les attaques non détectées
  par défaut
- Comparer plusieurs outils d'attaque (sqlmap, Burp Suite, OWASP ZAP)
- Documenter les faux positifs / faux négatifs rencontrés

## 📁 Structure du dépôt

```
.
├── README.md
├── screenshots/
├── configs/        # exports de config (sans données sensibles)
└── docs/           # notes détaillées
```

## ⚠️ Avertissement

Ce lab est réalisé à des fins pédagogiques, dans un environnement isolé. DVWA
est une application volontairement vulnérable : elle ne doit jamais être
exposée sur un réseau non contrôlé ou accessible depuis Internet.
