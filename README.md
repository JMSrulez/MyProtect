# MyProtect : MCP local UniFi Protect

Serveur MCP en lecture seule pour Hermes, heberge sur Ubuntu avec Docker :
inventaire des cameras, metadonnees NVR, captures temporaires et collecte des
nouveaux evenements. API officielle Protect uniquement, validee sur 7.3.70.

**Installation de la V1 : [guide Ubuntu / Docker / Hermes](docs/DEPLOYMENT.md).**
HTTPS obligatoire, jeton Bearer distinct de la cle Protect et stockage borne.
Pas de logs systeme, d'export video historique, de SSH ou d'outil d'ecriture.

Les outils sont `list_cameras`, `get_nvr_status`, `get_collector_status`,
`search_events`, `get_snapshot` et `read_snapshot`. La collecte alimente un
historique local partiel ; elle ne recupere pas l'historique anterieur du NVR.
Le serveur exige Python 3.11+ ; l'image Docker utilise Python 3.13.

## Diagnostics prealables

Ces scripts sont destines au serveur Ubuntu qui hebergera le MCP. Ils ne
constituent pas encore un serveur MCP et ne changent aucun parametre du NVR.
Python 3.10 ou plus recent est requis. Ne pas lancer le diagnostic avec sudo.

## Installation sur Ubuntu

Transferer ce dossier sur Ubuntu, puis se placer a sa racine. Si necessaire,
installer les prerequis avec les droits administrateur :

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv ca-certificates openssl
```

Creer l'environnement isole et installer la seule dependance du test WebSocket :

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-diagnostics.txt
.venv/bin/python -m unittest discover -s scripts -p 'test_diagnose_protect.py' -v
bash -n scripts/diagnose-protect.sh
```

L'installation utilise Internet/PyPI, mais ne transmet aucune donnee Protect.
Le diagnostic lui-meme communique uniquement avec l'adresse de console fournie,
avec resolution DNS locale/systeme si un nom est utilise. Les proxies HTTP
systeme ne sont pas utilises et les redirections ne sont pas suivies.

## Cle API

Creer manuellement une cle d'integration locale sur la console UniFi OS,
dans les integrations du panneau de controle (libelles selon version).
Verifier sa disponibilite sur cette console et ne pas confondre avec une cle
Site Manager cloud. Ne pas desactiver la MFA du compte principal.

La cle est demandee a chaque execution, sans affichage : ne pas la mettre dans
une ligne de commande, un fichier du projet, une variable exportee ou un message.
Elle reste en memoire du processus. Le script ne peut pas transformer une cle
native disposant d'ecriture en cle native de lecture seule.

## TLS : certificat obligatoire

Utiliser le nom DNS couvert par le certificat du NVR. Si son autorite est deja
approuvee par Ubuntu, aucune option supplementaire n'est necessaire.
Sinon, fournir une autorite ou un certificat PEM approuve avec `--ca-file`.
Le nom DNS ou l'adresse IP utilise doit aussi figurer dans les SAN du certificat.

Pour examiner le certificat presente, sans transmettre de cle API :

```bash
openssl s_client -connect uck.exemple.lan:443 -servername uck.exemple.lan </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName
```

Remplacer `uck.exemple.lan` par le nom de ta console. Comparer l'empreinte SHA-256
par un canal deja fiable, par exemple les details du certificat dans le navigateur
habituellement utilise pour administrer la console. La commande seule ne prouve
pas l'identite du serveur. Obtenir ensuite le PEM via ce canal fiable et le placer
dans `certs/uck-ca.pem`. Un certificat auto-signe doit etre explicitement approuve ;
un certificat signe doit utiliser son autorite de confiance.
Le script ne propose pas de mode insecure. Si le certificat n'a pas de SAN adapte,
il faut corriger le certificat ou le nom utilise avant le test authentifie.

## Test 1 : version, NVR et cameras

```bash
bash scripts/diagnose-protect.sh --console https://uck.exemple.lan --ca-file certs/uck-ca.pem
```

Supprimer `--ca-file certs/uck-ca.pem` si la chaine est deja approuvee par Ubuntu.
Le diagnostic appelle uniquement ces routes locales, avec `X-API-KEY` :

- `GET /proxy/protect/integration/v1/meta/info`
- `GET /proxy/protect/integration/v1/nvrs`
- `GET /proxy/protect/integration/v1/cameras`

Il s'arrete en cas de rejet d'authentification, de limite de requetes, d'erreur TLS
ou de transport. Les corps d'erreur ne sont jamais affiches ni sauvegardes.
Une reponse HTML de connexion n'est pas consideree comme un succes.

Chaque execution cree un dossier `protect-diagnostic-...` prive dans la racine
du projet. `report.json` contient uniquement les statuts, compteurs et la version
d'application si elle a ete retournee. `target_version` indique la version visee,
pas une version detectee. Consulter `cameras.private.json` localement pour choisir
l'ID d'une camera ; ce fichier contient aussi les noms et etats des cameras.

## Test 2 : une photo explicite

Remplacer `ID_CAMERA` par un ID present dans l'inventaire :

```bash
bash scripts/diagnose-protect.sh --console https://uck.exemple.lan --ca-file certs/uck-ca.pem --camera-id ID_CAMERA
```

Le script repete les controles de base puis demande une seule capture par
`GET /v1/cameras/{id}/snapshot`. Il verifie le type et la signature JPEG/PNG avant
de creer `snapshot.jpg` ou `snapshot.png`. Limite : 16 Mio par capture.

## Test 3 : evenements en direct pendant 60 secondes

```bash
bash scripts/diagnose-protect.sh --console https://uck.exemple.lan --ca-file certs/uck-ca.pem --events-seconds 60
```

Le test ouvre `wss://.../proxy/protect/integration/v1/subscribe/events`.
Pendant l'ecoute, provoquer une detection non dangereuse, par exemple passer
devant une camera, sans declencher volontairement une sirene.
Par defaut, seuls les compteurs sont conserves. Ajouter `--save-events` pour
enregistrer les messages bruts dans `events.private.jsonl` si leur analyse est
necessaire. Ils peuvent contenir des informations personnelles.

Une connexion reussie avec zero message valide l'ouverture du flux, pas la
reception effective des detections. Le flux ne remplace pas un historique
d'alarmes ou un journal systeme. Limites : 120 secondes, 100 messages,
64 Kio par message et environ 1 Mio cumule. Aucun webhook d'alarme n'est appele.

## Logs NVR et videos enregistrees : limites constatees

L'index officiel 7.3.70 ne documente ni consultation de logs systeme, ni recherche
historique REST d'evenements, ni export de video enregistree. Ces fonctions sont
marquees comme non testees dans le rapport ; aucune route privee n'est sondee et
aucune connexion SSH n'est effectuee. Cela ne prouve pas que le NVR est incapable
de fournir ces donnees, seulement que cette interface ne les documente pas.

Les routes RTSPS documentees concernent le direct, pas l'export d'enregistrements.
Le diagnostic ne cree pas de flux RTSPS et ne confond pas sa disponibilite avec
la recuperation d'une video historique. Les tests videos/logs necessiteront une
decision ulterieure sur une interface supplementaire prise en charge.

## Resultats a communiquer

Retourner uniquement `report.json`, apres relecture. Ne pas transmettre les cles,
certificats prives, inventaires, photos ou evenements bruts pour ce premier bilan.
Codes de sortie : 0 = controles executes reussis, 2 = au moins un echec ou argument
invalide, 130 = interruption. Un code 0 ne valide pas les fonctions non testees.

Les fichiers locaux ne sont pas purges automatiquement. Les supprimer apres
analyse, selon ta politique de conservation. Rien n'est envoye a Hermes ou a une IA.

## References

- https://developer.ui.com/protect/v7.3.70/llms.txt
- https://developer.ui.com/protect/v7.3.70/get-v1metainfo
- https://developer.ui.com/protect/v7.3.70/get-v1nvrs
- https://developer.ui.com/protect/v7.3.70/get-v1camerasidsnapshot
- https://developer.ui.com/protect/v7.3.70/get-v1subscribeevents