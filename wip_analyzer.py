from runpy import _ModifiedArgv0
from xml.dom import INVALID_MODIFICATION_ERR
from timesketch.lib.analyzers import interface
from timesketch.lib.analyzers import manager
from timesketch.lib import emojis

#1 Récupérer les hash dans timesktech


#2 Créer une liste avec les hash

#3 Requêter l'API Circl et lui soumettre la liste

##Pinger l'API Circl
curl -X 'GET' 'https://hashlookup.circl.lu/info' -H 'accept: application/json'

##SHA-256
curl -s -X 'GET'   'https://hashlookup.circl.lu/lookup/sha256/301c9ec7a9aadee4d745e8fd4fa659dafbbcc6b75b9ff491d14cbbdd840814e9'   -H 'accept: application/json' | jq

##Bulk search SHA-1
curl -X 'POST'   'https://hashlookup.circl.lu/bulk/sha1' -H "Content-Type: application/json"  -d "{\"hashes\": [\"FFFFFDAC1B1B4C513896C805C2C698D9688BE69F\", \"FFFFFF4DB8282D002893A9BAF00E9E9D4BA45E65\", \"FFFFFE4C92E3F7282C7502F1734B243FA52326FB\"]}" | jq .

##Bulk search MD5
curl -X 'POST'   'https://hashlookup.circl.lu/bulk/md5' -H "Content-Type: application/json"  -d "{\"hashes\": [\"6E2F8616A01725DCB37BED0A2495AEB2\", \"8ED4B4ED952526D89899E723F3488DE4\", \"344428FA4BA313712E4CA9B16D089AC4\"]}" | jq .

#4 Taguer les fichiers matchant la liste

# Identifier les fichiers ne matchant pas la liste

Dans le sketch
Evenement 
hashListe des hash 
contact

Mark event à _ModifiedArgv0

liste de hash tous les 25 hash envoie en bulk, envoie la réponse la traite et envoie le bulk suinvat
find INVALID_MODIFICATION_ERR
Parcourir les événements enregistrer les hash 