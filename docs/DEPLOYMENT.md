# V1 MCP : Ubuntu, Docker et Hermes

## Perimetre et protections

Cette V1 s'appuie uniquement sur les routes que les diagnostics ont validees :
metadonnees, NVR, cameras, captures et WebSocket des nouveaux evenements.
Les autres routes sont refusees par le connecteur, pas simplement masquees au modele.
Le transport est Streamable HTTP via HTTPS, avec un jeton Bearer personnel fixe.
Ce mode est compatible avec les en-tetes Hermes ; ce n'est pas un serveur OAuth
et il ne pretend pas implementer la decouverte d'autorisation OAuth MCP.

Le serveur n'appelle aucune IA. `get_snapshot` renvoie une reference et une URL
authentifiee. Seul `read_snapshot` retourne les pixels dans le resultat MCP.
Une fois recus par Hermes, ces pixels peuvent etre envoyes a son modele principal
ou auxiliaire selon sa configuration. Le choix du modele local Qwen reste a
configurer dans Hermes ; ce serveur ne peut pas imposer ce choix au client.

## 1. Recuperer et tester sur Ubuntu

Depuis le compte non-root qui gere le projet et les conteneurs :

```bash
git pull --ff-only
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m unittest discover -s scripts -p 'test_diagnose_protect.py' -v
docker compose version
```

Python 3.11+ est necessaire pour le serveur ; les diagnostics seuls restent
compatibles Python 3.10. Sur Ubuntu 22.04 sans Python recent, ne pas remplacer
le Python systeme : utiliser un interpreteur 3.11+ separe pour la preparation,
ou executer la preparation sur une machine Ubuntu recente. Le conteneur inclut
son propre Python 3.13. Aucun paquet Python du systeme n'est modifie.

## 2. Preparer les certificats

Deux confiances TLS distinctes sont necessaires :

- Ubuntu doit approuver le certificat de l'UCK : reutiliser le PEM deja valide
  avec les diagnostics, par exemple `certs/uck-ca.pem`.
- Hermes sur le Mac doit approuver le certificat du MCP : utiliser un certificat
  de ton autorite interne, avec le nom DNS choisi dans les SAN, et sa cle privee.

Exemple de nom : `protect-mcp.home.arpa`, resolu vers l'IP LAN d'Ubuntu depuis le
Mac. Il peut etre remplace par une IP si cette IP figure dans les SAN du certificat.
Le nom, le port et l'URL Hermes doivent correspondre a `MCP_PUBLIC_URL`.

Sans autorite interne, un certificat auto-signe dedie peut servir pour cette
installation personnelle. Remplacer le nom et l'adresse IP d'exemple :

```bash
umask 077
mkdir -p certs
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -noenc \
  -keyout certs/mcp-server.key -out certs/mcp-server.crt \
  -subj '/CN=protect-mcp.home.arpa' \
  -addext 'subjectAltName=DNS:protect-mcp.home.arpa,IP:192.168.1.20'
openssl x509 -in certs/mcp-server.crt -noout -fingerprint -sha256
```

La cle n'est pas chiffree pour permettre le demarrage autonome ; la proteger
avec les permissions du compte et le chiffrement du disque. Transferer uniquement
le certificat public vers le Mac via un canal fiable, verifier son empreinte,
puis le referencer via `ssl_verify` dans Hermes. Ne jamais transferer la cle
privee ni definir `ssl_verify: false`. Avec une autorite interne, transferer son
certificat public et servir la chaine intermediaire complete cote MCP.

## 3. Generer la configuration locale

Dans la racine du projet, en adaptant les adresses a ton reseau :

```bash
.venv/bin/python -m scripts.configure_server \
  --protect-url https://uck.exemple.lan \
  --public-url https://protect-mcp.home.arpa:8443 \
  --bind-ip 192.168.1.20 \
  --protect-ca certs/uck-ca.pem \
  --tls-cert certs/mcp-server.crt \
  --tls-key certs/mcp-server.key
```

La cle Protect est demandee sans affichage. Un jeton MCP different est genere.
Ajouter `--camera-id ID` autant de fois que necessaire pour restreindre les
cameras. En l'absence de liste, toutes les cameras accessibles par la cle sont
autorisees. Le nom de la console et ses metadonnees restent disponibles.

L'assistant cree `.env`, `.secrets/` et `data/`, exclus de Git et du contexte
Docker. Ces fichiers restent locaux. Il refuse root et toute configuration deja
presente. `.env` ne contient aucun secret ; les secrets sont des fichiers 0600
dans un dossier 0700. Les copies dans `.secrets/` sont celles effectivement lues
par le conteneur, pas les fichiers d'origine de `certs/`.

Sans `--bind-ip`, seul `127.0.0.1` est publie, donc le Mac ne peut pas se connecter.
Le port hote est 8443 ; ne pas choisir un autre port dans l'URL sans adapter aussi
le mappage de ports de Compose. L'UID/GID du compte est repris pour que le
conteneur non-root puisse lire les secrets et ecrire les donnees sans chmod large.
Le groupe Docker donne des pouvoirs importants sur l'hote : ne pas le donner a Hermes.

## 4. Pare-feu et lancement

Avant le lancement, autoriser uniquement l'IP du Mac vers l'IP Ubuntu et le port
8443. Aucun transfert de port sur le routeur, aucun acces Internet entrant.
Attention : les ports publies par Docker peuvent contourner les regles UFW
classiques. Appliquer le filtrage sur le pare-feu inter-VLAN ou dans la chaine
Docker appropriee (`DOCKER-USER` avec le backend iptables, equivalent avec nftables),
sans modifier les regles des autres conteneurs. Une liaison a l'IP LAN seule
ne constitue pas un filtrage par IP cliente.

Limiter aussi les sorties du service a l'IP de l'UCK sur TCP 443 (adapter si un
port different est utilise) et au DNS necessaire. Cette restriction reseau doit
etre configuree sur l'infrastructure ; Compose ne l'impose pas a lui seul.
Le build a besoin d'Internet pour l'image et les dependances, pas le service en execution.

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps
docker compose logs --tail=50 myprotect
```

Le service ecoute en HTTPS sans proxy supplementaire, ne fait pas confiance aux
en-tetes `X-Forwarded-*` et refuse un nom d'hote ou une origine non autorise.
Toutes les routes, y compris `/health` et `/media/...`, exigent le Bearer.
Le healthcheck Docker teste le port TCP, pas la reception des evenements : utiliser
`get_collector_status` pour cette derniere. L'image n'embarque ni secrets, ni
certificats, ni donnees. Un seul conteneur et un seul worker sont prevus.

## 5. Configurer Hermes sur le Mac

Transferer le jeton de `.secrets/mcp_token` vers le stockage de secrets Hermes par
un canal chiffre, sans le coller dans une conversation avec un agent. Stocker
la variable `MYPROTECT_MCP_TOKEN` dans le fichier de secrets du profil Hermes
(habituellement `~/.hermes/.env`), avec permissions 0600. Seul le jeton MCP va
sur le Mac ; la cle Protect reste sur Ubuntu.

Ajouter dans la configuration du profil Hermes, sous `mcp_servers` :

```yaml
mcp_servers:
  myprotect:
    url: "https://protect-mcp.home.arpa:8443/mcp"
    headers:
      Authorization: "Bearer ${MYPROTECT_MCP_TOKEN}"
    ssl_verify: "/Users/TON_COMPTE/.hermes/certs/myprotect-ca.pem"
    timeout: 90
    connect_timeout: 30
    supports_parallel_tool_calls: false
    sampling:
      enabled: false
    tools:
      include:
        - list_cameras
        - get_nvr_status
        - get_collector_status
        - search_events
        - get_snapshot
        - read_snapshot
      resources: false
      prompts: false
```

Le chemin `ssl_verify` designe le certificat public auto-signe ou l'autorite
interne verifiee. Si le certificat est deja approuve par l'environnement TLS
de Hermes, `ssl_verify: true` suffit. La configuration doit etre appliquee au
profil/processus qui tourne reellement sur le Mac, pas a celui d'un autre hote.
Ajouter le nom du MCP a `NO_PROXY` si Hermes utilise un proxy sortant.

```bash
hermes mcp test myprotect
```

Puis `/reload-mcp` dans Hermes, ou redemarrer son processus. Pour un profil
metadonnees seules, retirer `read_snapshot` de `tools.include` et ne pas accorder
a ce profil un outil HTTP pouvant telecharger les URLs de medias.
Les annotations MCP ne constituent pas une approbation de transmission d'images.

## 6. Recette de verification

1. Demander de lister les cameras : les cinq cameras attendues, ou la liste
   restreinte, doivent apparaitre.
2. Consulter `get_collector_status` : `connected` doit etre vrai. Provoquer une
   detection non dangereuse, puis verifier `events_stored` et `search_events`.
3. Demander `get_snapshot` sur une camera : la reponse contient une reference,
   une expiration et une URL qui exige une authentification.
4. Appeler `read_snapshot` uniquement avec le routage vision choisi dans Hermes.
   Verifier que le modele local traite l'image si c'est le mode souhaite.
5. Verifier depuis une autre machine que le pare-feu bloque le port 8443.

Les messages non reconnus ou sans camera identifiable ne sont pas stockes. Le
compteur `messages_received` peut donc exceder `events_stored`. Il ne faut pas
qualifier tous ces messages d'alarmes. Un refus 401/403 arrete les reconnexions
du collecteur jusqu'au redemarrage ; les autres ruptures declenchent un delai
progressif de 1 a 60 secondes. Les interruptions peuvent perdre des evenements,
sans rattrapage automatique de l'historique.

## Conservation et exploitation

- Evenements : sept jours maximum depuis la derniere reception locale, au plus
  10 000 evenements. Les mises a jour d'un meme ID sont fusionnees. La recherche
  filtre la date locale de reception, pas le debut historique de l'evenement.
- Photos : une heure maximum, 256 Mio et 1 000 fichiers maximum par defaut.
  Les plus anciennes peuvent etre supprimees avant expiration pour respecter le quota.
- Purge au demarrage, lors des acces et toutes les 30 secondes. Une reference
  expiree n'est plus servie ; le nettoyage disque periodique peut avoir 30 s de retard.
- Images MCP : limite de 6 Mio avant base64 ; les plus grandes restent disponibles
  par telechargement authentifie, jusqu'a 16 Mio maximum par capture.
- Audit : operations d'outils, lectures de medias et refus d'authentification bornes,
  sans jeton, cle, arguments bruts ni pixels ; 30 jours et 20 000 lignes maximum.
  Cet audit SQLite local n'est pas inviolable : l'administrateur de l'hote peut le modifier.
- SQLite est borne a environ 128 Mio. Logs Docker bornes a trois fichiers de 5 Mo.
  Donnees non chiffrees par l'application : proteger le disque, les sauvegardes et le compte.
- 60 requetes HTTP authentifiees par minute, corps de requete limite a 1 Mio,
  deux lectures NVR simultanees et huit connexions HTTP actives maximum.

Les parametres de retention/quota sont dans `compose.yaml`, avec des bornes
validees au demarrage. Pour arreter : `docker compose down` (les donnees restent).
Pour tourner un secret, modifier son fichier local avec un outil protege, puis
`docker compose up -d --force-recreate`. Pour renouveler TLS, remplacer aussi les
copies dans `.secrets/`, mettre a jour la confiance du Mac si necessaire et recreer
le conteneur. Ne pas relancer l'assistant pour ecraser une installation existante.

Les bibliotheques directes sont epinglees ; reconstruire et retester regulierement
pour les correctifs de securite. Les dependances transitives et l'image de base
ne sont pas verrouillees par digest : ce n'est pas un build bit-a-bit reproductible.

## Limites et diagnostic

Les logs systeme NVR, la recherche de l'historique anterieur et l'export video
enregistree ne sont pas exposes. Aucun SSH, flux RTSPS cree ou API privee utilisee.
Un filtrage interne au MCP ne reduit pas les droits natifs de la cle Protect :
une compromission du conteneur peut toujours exposer cette cle. Le filtrage reseau,
les mises a jour, la separation d'hote et les sauvegardes restent essentiels.

401 : verifier le jeton ; 403 : verifier Origin ; 421 : verifier URL/Host ;
429 : attendre et reduire la frequence ; erreur TLS : verifier les certificats,
SAN, expiration et horloge. Ne jamais contourner une erreur TLS en desactivant
la verification. Les tests automatises utilisent un NVR simule et des certificats
locaux ; la recette sur ton Ubuntu et ton installation Hermes reste necessaire.

References : [SDK MCP officiel](https://github.com/modelcontextprotocol/python-sdk),
[API Protect 7.3.70](https://developer.ui.com/protect/v7.3.70/llms.txt),
[configuration Hermes](https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference).