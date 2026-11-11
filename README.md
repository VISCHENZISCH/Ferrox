<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
    <img src="docs/logo-light.svg" alt="Ferrox" width="260">
  </picture>
</p>

<p align="center">Proxy web et DNS de surveillance réseau, en Rust, pour les labos et l'usage personnel.</p>

<p align="center">
  <img src="docs/badges/rust.svg" alt="Rust" height="28">
  <img src="docs/badges/git.svg" alt="Git" height="28">
  &nbsp;
  <img src="docs/badges/linux.svg" alt="Linux" height="28">
  <img src="docs/badges/windows.svg" alt="Windows" height="28">
  <img src="docs/badges/macos.svg" alt="macOS" height="28">
</p>

---

| | |
|---|---|
| <img src="docs/icons/list.svg" width="20"> **Journaliser** | Qui contacte quel domaine, quand, avec quel volume. Format JSON Lines ECS, syslog en option. |
| <img src="docs/icons/filter.svg" width="20"> **Filtrer** | Listes de blocage (malware, phishing, pub), catégories UT1, domaines, extensions et signatures de fichiers. |
| <img src="docs/icons/alert.svg" width="20"> **Détecter** | Balises C2, exfiltration, User-Agent suspects. |
| <img src="docs/icons/dns.svg" width="20"> **DNS intégré** | Filtrage, cache, détection DGA, tunnels et rafales de NXDOMAIN. |
| <img src="docs/icons/lock.svg" width="20"> **Interception TLS** | En option, pour voir les URL, User-Agent et fichiers en HTTPS. |
| <img src="docs/icons/traffic.svg" width="20"> **Capture** | Proxy explicite, ou transparent (HTTP, et HTTPS par SNI). |
| <img src="docs/icons/lock.svg" width="20"> **Contrôle d'accès** | Réseaux clients autorisés, ports CONNECT, authentification Basic, limites de connexions. |

## Installer

Les exécutables de chaque version sont sur la page [Releases](https://github.com/VISCHENZISCH/Ferrox/releases) :

| Système | Archive | Contenu |
|---|---|---|
| Linux x86-64 | `ferrox-<version>-linux-x86_64.tar.gz` | `ferrox`, `ferroxd`, unité systemd |
| Windows x86-64 | `ferrox-<version>-windows-x86_64.zip` | `ferrox.exe`, `ferroxd.exe` |
| macOS (Apple Silicon et Intel) | `ferrox-<version>-macos-universal.tar.gz` | `Ferrox.app`, `ferrox`, `ferroxd` |

`SHA256SUMS.txt` donne les sommes de contrôle. Les binaires ne sont pas signés par un éditeur : sous macOS, autorisez l'application avec `xattr -dr com.apple.quarantine Ferrox.app` ; sous Windows, SmartScreen demande une confirmation au premier lancement.

L'application de bureau a besoin d'un pilote graphique Vulkan, Metal, DirectX 12 ou OpenGL ; sous Linux, des bibliothèques `libxkbcommon` et Wayland ou X11 de la session.

## Compiler

```sh
cargo build --release
./target/release/ferrox      # application de bureau (Linux, Windows, macOS)
./target/release/ferroxd     # service sans interface
```

Réglez ensuite le navigateur ou le système sur le proxy `127.0.0.1:3128`. Le DNS écoute sur `127.0.0.1:5335`.

Commandes du service : `ferroxd [run | init | check | update-lists | ca | version] [-c config.toml]`.

## Configuration

Le fichier `~/.config/ferrox/config.toml` est créé au premier lancement. Toutes les options sont dans [config/ferrox.example.toml](config/ferrox.example.toml).

**Journaux** : dans `~/.local/share/ferrox/logs/`, un fichier `traffic-AAAA-MM-JJ.jsonl` et un fichier `alerts-AAAA-MM-JJ.jsonl` par jour.

**Accès** : par défaut, seuls les clients de la boucle locale sont acceptés. Pour servir un réseau, listez-le dans `[proxy] allow` et `[dns] allow`, par exemple `["127.0.0.0/8", "192.168.1.0/24"]`. CONNECT est limité aux ports 443 et 8443 (`connect_ports`). L'authentification Basic s'active avec `[proxy.auth]`.

**Interception TLS** : activez-la dans Paramètres, puis installez `ferrox-ca.pem` (bouton « Générer la CA » ou `ferroxd ca`) comme autorité racine sur les postes. Gardez la clé `ferrox-ca.key` privée.

**Mode transparent** (Ferrox en passerelle Linux) : redirigez le trafic vers les ports transparents, puis renseignez-les dans `[proxy]`.

```sh
iptables -t nat -A PREROUTING -i <lan> -p tcp --dport 80  -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i <lan> -p tcp --dport 443 -j REDIRECT --to-port 8443
```

**Raccourcis** : `Ctrl+1` à `Ctrl+6` pour changer de page, `Ctrl+T` pour le thème, `Ctrl+P` pour mettre en pause.

## Structure

```
crates/ferrox-core      moteur : proxy, DNS, filtrage, détection, journaux
crates/ferrox-desktop   interface (iced)
crates/ferrox-cli       service ferroxd
```

Tests : `cargo test --workspace` (unitaires et intégration proxy/DNS). Vérifications de la CI : `make check`.

Service Linux : voir [packaging/ferroxd.service](packaging/ferroxd.service). Historique : [CHANGELOG.md](CHANGELOG.md). Documentation technique : [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md).

## Licence

MIT. Les polices IBM Plex Sans et JetBrains Mono sont sous licence OFL. Les icônes et le logo ont été dessinés pour le projet.
