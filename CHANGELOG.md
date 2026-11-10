# Changelog

Toutes les évolutions notables de Ferrox sont décrites ici.
Format [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions [SemVer](https://semver.org/lang/fr/).

## [0.2.0] - 2026-11-10

Version « Rempart » : sécuriser l'exposition. Aucun constat critique ou majeur du cahier des charges ne reste ouvert.

### Sécurité
- Listes de réseaux autorisés pour le proxy et le DNS, refus par défaut hors boucle locale (`[proxy] allow`, `[dns] allow`) ; avertissement si un écouteur sur `0.0.0.0` est ouvert à tous (FP-01, C-01).
- CONNECT limité aux ports 443 et 8443 par défaut (`connect_ports`) : plus de relais SMTP ni d'accès aux services internes sur d'autres ports (FP-02, C-03).
- Exclusion d'interception TLS temporaire : 3 échecs avant le tunnel direct, durée 1 h, table bornée ; un seul échec ne suffit plus à soustraire un domaine à l'inspection (FP-03, C-02).
- Réponse DNS amont acceptée seulement si l'identifiant et la question correspondent (C-14).

### Ajouté
- Authentification Basic facultative du proxy explicite (`[proxy.auth]`), comparaison en temps constant (FP-06).
- Délai d'inactivité sur les tunnels (`idle_timeout_s`) et plafond de connexions du proxy (`max_connections`) (FP-04, C-04).
- `ferroxd check` (vérifie la configuration) et `ferroxd version`.
- Champs « Clients autorisés », « Ports CONNECT » et identifiants dans la page Paramètres.
- Tests d'intégration du proxy et du DNS : relais, blocage, refus d'un client hors liste, ports CONNECT, authentification, cache, rechargement à chaud avec un tunnel ouvert.
- `Makefile`, `rustfmt.toml`, `.editorconfig`, licence MIT, unité systemd `packaging/ferroxd.service`.
- Intégration continue (fmt, clippy, tests sur Linux, Windows et macOS) et publication automatique des exécutables.

### Modifié
- Les seuils de détection enregistrés dans l'interface s'appliquent à chaud, sans redémarrer le moteur ni perdre les statistiques (FP-05, C-16).
- `idle_timeout_s` désigne désormais l'inactivité des tunnels ; l'attente de la réponse amont a sa propre clé `response_timeout_s` (60 s) (C-19).
- Profil release : `panic = "unwind"` et `overflow-checks = true` ; une panique dans une tâche réseau n'arrête plus tout le service (C-18).
- Les écouteurs affichent l'adresse réellement ouverte (utile avec le port 0).
- `Detector::alert` prend une structure `AlertSpec` au lieu de dix paramètres (C-22) ; plus aucun avertissement clippy par défaut (ENF-09) ; `#![allow(dead_code)]` global retiré (C-23).

### Corrigé
- DNS sur TCP : délai sur toute la lecture d'un message et plafond de connexions simultanées (`max_tcp_clients`) (C-05).
- Signatures de fichiers inspectées sur les 36 premiers Kio, après décompression gzip ou deflate : la signature ISO et les exécutables compressés sont reconnus (C-06).
- Une liste téléchargée sans aucun domaine (page HTML, réponse vide) ne remplace plus la précédente ; écriture atomique (C-07).
- Résolveurs amont IPv6 sans port (`2606:4700::1111`) acceptés ; une valeur invalide arrête le démarrage au lieu d'être ignorée (C-08).
- Tables des clients et des domaines bornées : le dixième le plus ancien est retiré au-delà de 50 000 entrées (C-10).
- Alertes User-Agent : la chaîne va dans `user_agent.original`, plus dans `destination.domain` ; score arrondi à deux décimales (C-12).
- Cache DNS : une réponse trop grande pour le client UDP est signalée tronquée (TC) au lieu d'être envoyée (C-13).
- `ferroxd` écrit toutes les nouvelles alertes, même en rafale (C-21).

### Migration
- Un proxy ou un DNS utilisé depuis d'autres machines doit maintenant lister leurs réseaux dans `allow`, par exemple `allow = ["127.0.0.0/8", "192.168.1.0/24"]`.
- Les clients qui utilisaient CONNECT vers d'autres ports que 443 et 8443 doivent les ajouter à `connect_ports`.

## [0.1.0] - 2026-11-08

Première version : proxy explicite et transparent, DNS filtrant avec cache, interception TLS facultative, journaux ECS, 14 règles de détection, application de bureau et service `ferroxd`.

[0.2.0]: https://github.com/VISCHENZISCH/Ferrox/releases/tag/v0.2.0
