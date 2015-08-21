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


def OpStatus(dtssStatus):
    response = []
    if dtssStatus is None:
        return response

    if dtssStatus is 0:
        response.append((TypeReponse.SUCCES, "Traitement effectué avec succès"))
    elif dtssStatus is 11:
        response.append((TypeReponse.ERREUR, "Structure de signature, de certificat ou de jeton d\'authentification invalide"))
    elif dtssStatus is 12:
        response.append((TypeReponse.ERREUR, "Taille d\'un champ supérieure à la taille maximale autorisée ou champ vide (si obligatoire)"))
    elif dtssStatus is 13:
        response.append((TypeReponse.ERREUR, "Taille de la requête supérieure à la taille maximale autorisée dans la politique de confiance"))
    elif dtssStatus is 14:
        response.append((TypeReponse.ERREUR, "Format de la requête incorrect"))
    elif dtssStatus is 15:
        response.append((TypeReponse.ERREUR, "Données manquantes dans la requête"))
    elif dtssStatus is 16:
        response.append((TypeReponse.ERREUR, "Mauvais format de signature"))
    elif dtssStatus is 17:
        response.append((TypeReponse.ERREUR, "Mauvais type de signature"))
    elif dtssStatus is 18:
        response.append((TypeReponse.ERREUR, "Erreur au moment du traitement pas un plugin"))
    elif dtssStatus is 19:
        response.append((TypeReponse.ERREUR, "Noeud de signature non trouvé"))
    elif dtssStatus is 21:
        response.append((TypeReponse.ERREUR, "Application non-autorisée"))
    elif dtssStatus is 22:
        response.append((TypeReponse.ERREUR, "Transaction inconnue"))
    elif dtssStatus is 23:
        response.append((TypeReponse.ERREUR, "Type de requête non autorisée"))
    elif dtssStatus is 26:
        response.append((TypeReponse.ERREUR, "Application désactivée"))
    elif dtssStatus is 27:
        response.append((TypeReponse.ERREUR, "Clé cryptographique invalide/inaccessible"))
    elif dtssStatus is 31:
        response.append((TypeReponse.ERREUR, "Service DTSSService injoignable"))
    elif dtssStatus is 32:
        response.append((TypeReponse.ERREUR, "Problème d'accès à la base de données"))
    elif dtssStatus is 33:
        response.append((TypeReponse.ERREUR, "Problème lors de la pose d\'un jeton d'horodatage"))
    elif dtssStatus is 61:
        response.append((TypeReponse.ERREUR, "Erreur de vérification du temps de dérive"))
    elif dtssStatus is 90:
        response.append((TypeReponse.ERREUR, "Erreur d\'exécution du Plugin Post-Action (Archivage externe...)"))
    elif dtssStatus is 99:
        response.append((TypeReponse.ERREUR, "Erreur interne DVS"))
    else:
        response.append((TypeReponse.ERREUR, "Erreur normalement non référencée"))

    return response


class DTSSStatus(Enum):
    NA_x8000 = 0x8000
    CERTIFICAT_ENTITE_INVALID = 0x4000
    HORADATAGE_IMPOSSIBLE = 0x2000
    DOC_SEMANTIC_NA = 0x1800
    DOCUMENT_INSTABLE = 0x1000
    DOCUMENT_STABLE = 0x0800
    NA_x0400 = 0x0400
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


def DTSSGlobalStatus(leCode):
    response = []
    if leCode is None:
        return response


    if ((leCode & DTSSStatus.CERTIFICAT_ENTITE_INVALID.value) == DTSSStatus.CERTIFICAT_ENTITE_INVALID.value):
        response.append((TypeReponse.ERREUR, "Certificat entité invalide"))
    else:
        response.append((TypeReponse.SUCCES, "Certificat entité valide"))

    if ((leCode & DTSSStatus.HORADATAGE_IMPOSSIBLE.value) == DTSSStatus.HORADATAGE_IMPOSSIBLE.value):
        response.append((TypeReponse.ERREUR, "Horodatage de réception de la signature impossible"))
    else:
        response.append((TypeReponse.SUCCES, "Horodatage de réception de la signature effectué (ou non demandé)"))

    if ((leCode & DTSSStatus.DOC_SEMANTIC_NA.value) == DTSSStatus.DOC_SEMANTIC_NA.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))
    elif ((leCode & DTSSStatus.DOCUMENT_INSTABLE.value) == DTSSStatus.DOCUMENT_INSTABLE.value):
        response.append((TypeReponse.ERREUR, "Stabilité sémantique du document : instable"))
    elif ((leCode & DTSSStatus.DOCUMENT_STABLE.value) == DTSSStatus.DOCUMENT_STABLE.value):
        response.append((TypeReponse.SUCCES, "Stabilité sémantique du document : stable"))
    else:
        response.append((TypeReponse.NEUTRE, "Vérification de la stabilité sémantique du document non demandée"))

    if ((leCode & DTSSStatus.NA_x8000.value) == DTSSStatus.NA_x8000.value
        or (leCode & DTSSStatus.NA_x0400.value) == DTSSStatus.NA_x0400.value
        or (leCode & DTSSStatus.NA_x0200.value) == DTSSStatus.NA_x0200.value
        or (leCode & DTSSStatus.NA_x0100.value) == DTSSStatus.NA_x0100.value
        or (leCode & DTSSStatus.NA_x0080.value) == DTSSStatus.NA_x0080.value
        or (leCode & DTSSStatus.NA_x0040.value) == DTSSStatus.NA_x0040.value
        or (leCode & DTSSStatus.NA_x0020.value) == DTSSStatus.NA_x0020.value
        or (leCode & DTSSStatus.NA_x0010.value) == DTSSStatus.NA_x0010.value
        or (leCode & DTSSStatus.NA_x0008.value) == DTSSStatus.NA_x0008.value
        or (leCode & DTSSStatus.NA_x0004.value) == DTSSStatus.NA_x0004.value
        or (leCode & DTSSStatus.NA_x0002.value) == DTSSStatus.NA_x0002.value
        or (leCode & DTSSStatus.NA_x0001.value) == DTSSStatus.NA_x0001.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))

    return response


if __name__ == "__main__":
    try:

        parser = argparse.ArgumentParser(description='DTSS caller.')
        parser.add_argument('opStatus', metavar='--opStatus', type=int, help='opStatus')
        parser.add_argument('--globalStatus', metavar='-globalStatus', type=int, help='globalStatus')

        args = parser.parse_args()

        print 'OpStatus \t:', args.opStatus
        print pprint(OpStatus(args.opStatus))

        if args.globalStatus is not None :
            print 'DTSSGlobalStatus\t:', args.globalStatus
            print pprint(DTSSGlobalStatus(args.globalStatus))

    except Exception as e:
        print e
        traceback.print_exc(file=sys.stdout)
        sys.exit(3)