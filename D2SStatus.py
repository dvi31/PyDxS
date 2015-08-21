#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

from enum import Enum
import argparse, traceback, sys


class TypeReponse(Enum):
    ERREUR = "-"
    NEUTRE = " "
    SUCCES = "+"


def pprint(results):
    monBuffer = ""
    for result in results:
        monBuffer += (" [") + result[0].value + "] " + result[1] + "\n"
    return monBuffer


def OpStatus(d2sStatus):
    response = []
    if d2sStatus is None:
        return response

    if d2sStatus is 0:
        response.append((TypeReponse.SUCCES, "Traitement effectué avec succès"))
    elif d2sStatus is 11:
        response.append(
            (TypeReponse.ERREUR, "Structure de signature, de certificat ou de jeton d\'authentification invalide"))
    elif d2sStatus is 12:
        response.append((TypeReponse.ERREUR,
                         "Taille d\'un champ supérieure à la taille maximale autorisée ou mauvais paramètre de signature"))
    elif d2sStatus is 13:
        response.append((TypeReponse.ERREUR,
                         "Taille de la requête supérieure à la taille maximale autorisée dans la politique de confiance"))
    elif d2sStatus is 14:
        response.append((TypeReponse.ERREUR, "Format de la requête incorrect"))
    elif d2sStatus is 15:
        response.append((TypeReponse.ERREUR, "Données manquantes dans la requête"))
    elif d2sStatus is 16:
        response.append((TypeReponse.ERREUR, "Mauvais format de signature"))
    elif d2sStatus is 17:
        response.append((TypeReponse.ERREUR, "Mauvais type de signature"))
    elif d2sStatus is 18:
        response.append((TypeReponse.ERREUR, "Erreur au moment du traitement par un plugin"))
    elif d2sStatus is 19:
        response.append((TypeReponse.ERREUR, "Noeud de signature non trouvé"))
    elif d2sStatus is 21:
        response.append((TypeReponse.ERREUR, "Application non-autorisée"))
    elif d2sStatus is 22:
        response.append((TypeReponse.ERREUR, "Transaction inconnue"))
    elif d2sStatus is 23:
        response.append((TypeReponse.ERREUR, "Type de requête non autorisée"))
    elif d2sStatus is 26:
        response.append((TypeReponse.ERREUR, "Application désactivée"))
    elif d2sStatus is 27:
        response.append((TypeReponse.ERREUR, "Clé cryptographique invalide"))
    elif d2sStatus is 31:
        response.append((TypeReponse.ERREUR, "Service D2SService injoignable"))
    elif d2sStatus is 32:
        response.append((TypeReponse.ERREUR, "Problème d'accès à la base de données"))
    elif d2sStatus is 33:
        response.append((TypeReponse.ERREUR, "Problème lors de l'appel au serveur d'horodatage"))
    elif d2sStatus is 90:
        response.append((TypeReponse.ERREUR, "Erreur d\'exécution du Plugin Post-Action (Archivage externe...)"))
    elif d2sStatus is 99:
        response.append((TypeReponse.ERREUR, "Erreur interne D2S"))
    else:
        response.append((TypeReponse.ERREUR, "Erreur normalement non référencée"))

    return response


class D2SStatus(Enum):
    NA_x8000 = 0x8000
    CERTIFICAT_ENTITE_INVALID = 0x4000
    HORADATAGE_IMPOSSIBLE = 0x2000
    DOC_SEMANTIC_NA = 0x1800
    DOCUMENT_INSTABLE = 0x1000
    DOCUMENT_STABLE = 0x0800
    ALGORITHME_HASH_EXPIRE = 0x0400
    NA_x0200 = 0x0200
    NA_x0100 = 0x0100
    NA_x0080 = 0x0080
    NA_x0040 = 0x0040
    NA_x0020 = 0x0020
    NA_x0010 = 0x0010
    NA_x0008 = 0x0008
    NA_x0004 = 0x0004
    NA_x0002 = 0x0002
    NA_x0001 = 0x0001
    NO_ERROR = 0x0000


def D2SGlobalStatus(d2sStatus):
    response = []
    if d2sStatus is None:
        return response

    if ((d2sStatus & D2SStatus.CERTIFICAT_ENTITE_INVALID.value) == D2SStatus.CERTIFICAT_ENTITE_INVALID.value):
        response.append((TypeReponse.ERREUR, "Certificat entité invalide"))
    else:
        response.append((TypeReponse.SUCCES, "Certificat entité valide"))

    if ((d2sStatus & D2SStatus.HORADATAGE_IMPOSSIBLE.value) == D2SStatus.HORADATAGE_IMPOSSIBLE.value):
        response.append((TypeReponse.ERREUR, "Horodatage de réception de la signature impossible"))
    else:
        response.append((TypeReponse.SUCCES, "Horodatage de réception de la signature effectué (ou non demandé)"))

    if ((d2sStatus & D2SStatus.DOC_SEMANTIC_NA.value) == D2SStatus.DOC_SEMANTIC_NA.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))
    elif ((d2sStatus & D2SStatus.DOCUMENT_INSTABLE.value) == D2SStatus.DOCUMENT_INSTABLE.value):
        response.append((TypeReponse.ERREUR, "Stabilité sémantique du document : instable"))
    elif ((d2sStatus & D2SStatus.DOCUMENT_STABLE.value) == D2SStatus.DOCUMENT_STABLE.value):
        response.append((TypeReponse.SUCCES, "Stabilité sémantique du document : stable"))
    else:
        response.append((TypeReponse.NEUTRE, "Vérification de la stabilité sémantique du document non demandée"))

    if ((d2sStatus & D2SStatus.ALGORITHME_HASH_EXPIRE.value) == D2SStatus.ALGORITHME_HASH_EXPIRE.value):
        response.append((TypeReponse.ERREUR, "Algorithme de hash expiré"))
    else:
        response.append((TypeReponse.SUCCES, "Algorithme de hash valide"))

    if ((d2sStatus & D2SStatus.NA_x8000.value) == D2SStatus.NA_x8000.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0200.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0100.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0080.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0040.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0020.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0010.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0008.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0004.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0002.value
        or (d2sStatus & D2SStatus.NA_x0200.value) == D2SStatus.NA_x0001.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))

    return response

if __name__ == "__main__":
    try:

        parser = argparse.ArgumentParser(description='D2S caller.')
        parser.add_argument('opStatus', metavar='--opStatus', type=int, help='opStatus')
        parser.add_argument('--globalStatus', metavar='-globalStatus', type=int, help='globalStatus')

        args = parser.parse_args()

        print 'OpStatus \t:', args.opStatus
        print pprint(OpStatus(args.opStatus))

        if args.globalStatus is not None :
            print 'D2SGlobalStatus\t:', args.globalStatus
            print pprint(D2SGlobalStatus(args.globalStatus))

    except Exception as e:
        print e
        traceback.print_exc(file=sys.stdout)
        sys.exit(3)