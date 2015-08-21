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


def OpStatus(leCode):
    response = []

    if leCode is 0:
        response.append((TypeReponse.SUCCES, "Traitement effectué avec succès"))
    elif leCode is 11:
        response.append((TypeReponse.ERREUR,
                         "Structure de signature, de certificat ou de jeton d\'authentification invalide"))

    elif leCode is 12:
        response.append((TypeReponse.ERREUR,
                         "Taille d\'un champ supérieure à la taille maximale autorisée ou champ vide (si obligatoire)"))
    elif leCode is 13:
        response.append((TypeReponse.ERREUR,
                         "Taille de la requête supérieure à la taille maximale autorisée dans la politique de confiance"))
    elif leCode is 14:
        response.append((TypeReponse.ERREUR, "Format de la requête incorrect"))
    elif leCode is 15:
        response.append((TypeReponse.ERREUR, "Données manquantes dans la requête"))
    elif leCode is 16:
        response.append((TypeReponse.ERREUR, "Format de signature non autorisé"))
    elif leCode is 21:
        response.append((TypeReponse.ERREUR, "Application non-autorisée"))
    elif leCode is 22:
        response.append((TypeReponse.ERREUR, "Transaction inconnue"))
    elif leCode is 23:
        response.append((TypeReponse.ERREUR, "Type de requête non autorisée"))
    elif leCode is 26:
        response.append((TypeReponse.ERREUR, "Application désactivée"))
    elif leCode is 31:
        response.append((TypeReponse.ERREUR, "Service DVSService injoignable"))
    elif leCode is 32:
        response.append((TypeReponse.ERREUR, "Problème d'accès à la base de données"))
    elif leCode is 33:
        response.append((TypeReponse.ERREUR, "Problème lors de l'appel au serveur d'horodatage"))
    elif leCode is 41:
        response.append((TypeReponse.ERREUR, "Erreur du module de complètement AdES de la signature"))
    elif leCode is 90:
        response.append((TypeReponse.ERREUR, "Erreur d\'exécution du Plugin Post-Action (Archivage externe...)"))
    elif leCode is 99:
        response.append((TypeReponse.ERREUR, "Erreur interne DVS"))
    else:
        response.append((TypeReponse.ERREUR, "Erreur normalement non référencée"))

    return response


class DVSStatusCodeSign(Enum):
    VERIFICATION_ERROR = 0x80000000
    CERTIFICAT_EXPIRE = 0x40000000
    CERTIFICAT_NOT_LISTED = 0x20000000
    CERTIFICAT_DN_NOT_LISTED = 0x10000000
    KEY_USAGE_NOT_COMPLIANT = 0x08000000
    OID_NON_AUTORISE = 0x04000000
    QCSTATEMENTS_NOT_COMPLIANT = 0x02000000
    BUSINESS_CRL_INVALID = 0x01000000
    ALGORITHME_INTERDIT = 0x00800000
    NA_x00000040 = 0x00400000
    AC_HORS_VALIDITE = 0x00300000
    AC_REVOQUEE = 0x00200000
    AC_DONNEES_VALIDATION_MANQUANTE = 0x00100000
    VALIDATION_OCSP_NA = 0x000C0000
    VALIDATION_OCSP_DISPONIBLE = 0x00080000
    VALIDATION_OCSP_CERT = 0x00040000
    CERTIFICAT_AC_NON_AUTORISE = 0x00030000
    CERTIFICAT_DONNEES_VALIDATION_MANQUANTE = 0x00020000
    CERTIFICAT_REVOQUE = 0x00010000
    HORODATE_IMPOSSIBLE = 0x00008000
    SIGNATURE_INCOMPLIANT = 0x00004000
    DOC_SEMANTIC_NA = 0x00003000
    DOC_SEMANTIC_IMPOSSIBLE = 0x00002000
    DOC_SEMANTIC_INSTABLE = 0x00001000
    SIGNATURE_INVALID = 0x00000800
    TEMPORAL_WINDOW_OUT = 0x00000400
    HORODATAGE_INVALID = 0x00000200
    REFERENCE_NOT_FOUND = 0x00000100
    ADES_REF_INCOHERENT = 0x00000080
    XADES_ATTRIBUTE_NOT_FOUND = 0x00000040
    NA_x00000020 = 0x00000020
    NA_x00000010 = 0x00000010
    NA_x00000008 = 0x00000008
    NA_x00000004 = 0x00000004
    NA_x00000002 = 0x00000002
    NA_x00000001 = 0x00000001
    NO_ERROR = 0x00000000


class DVSGlobalStatusCodeSign(Enum):
    NA_x8000 = 0x8000
    INVALID_SIGNATURE = 0x4000
    CRL_UPDATE_ERROR = 0x2000
    COMPLETION_ERROR = 0x1000
    NA_x0800 = 0x0800
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


class DVSGlobalStatusCodeCert(Enum):
    NA_x8000 = 0x8000
    INVALID_CERT = 0x4000
    CRL_UPDATE_ERROR = 0x2000
    COMPLETION_ERROR = 0x1000
    NA_x0800 = 0x0800
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


class DVSStatusCodeCert(Enum):
    CERTIFICATE_INVALID = 0x80000000
    CERTIFICAT_EXPIRE = 0x40000000
    CERTIFICAT_NOT_LISTED = 0x20000000
    CERTIFICAT_DN_NOT_LISTED = 0x10000000
    KEY_USAGE_NOT_COMPLIANT = 0x08000000
    OID_NON_AUTORISE = 0x04000000
    QCSTATEMENTS_NOT_COMPLIANT = 0x02000000
    BUSINESS_CRL_INVALID = 0x01000000
    ALGORITHME_INTERDIT = 0x00800000
    NA_x0040 = 0x00400000
    NA_x0020 = 0x00200000
    NA_x0010 = 0x00100000
    NA_x000C = 0x000C0000
    VALIDATION_OCSP_DISPONIBLE = 0x00080000
    VALIDATION_OCSP_CERT = 0x00040000
    CERTIFICAT_AC_NON_AUTORISE = 0x00030000
    CERTIFICAT_DONNEES_VALIDATION_MANQUANTE = 0x00020000
    CERTIFICAT_REVOQUE = 0x00010000


def DVSGlobalStatusCert(leCode):
    response = []
    if leCode is None:
        return response

    if ((leCode & DVSGlobalStatusCodeCert.INVALID_CERT.value) == DVSGlobalStatusCodeCert.INVALID_CERT.value):
        response.append((TypeReponse.ERREUR, "Le certificat est invalide"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Le certificat est valide (tous les contrôles effectués ont retournés le résultats attendu)"))

    if ((leCode & DVSGlobalStatusCodeCert.CRL_UPDATE_ERROR.value) == DVSGlobalStatusCodeCert.CRL_UPDATE_ERROR.value):
        response.append((TypeReponse.ERREUR, "Mise à jour des CRLs impossible"))
    else:
        response.append(
            (TypeReponse.SUCCES, "Mise à jour des CRLs forcée avant exécution ou mise à jour non demandée"))

    if ((leCode & DVSGlobalStatusCodeCert.NA_x8000.value) == DVSGlobalStatusCodeCert.NA_x8000.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0800.value) == DVSGlobalStatusCodeCert.NA_x0800.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0400.value) == DVSGlobalStatusCodeCert.NA_x0400.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0200.value) == DVSGlobalStatusCodeCert.NA_x0200.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0100.value) == DVSGlobalStatusCodeCert.NA_x0100.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0080.value) == DVSGlobalStatusCodeCert.NA_x0080.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0040.value) == DVSGlobalStatusCodeCert.NA_x0040.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0020.value) == DVSGlobalStatusCodeCert.NA_x0020.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0010.value) == DVSGlobalStatusCodeCert.NA_x0010.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0008.value) == DVSGlobalStatusCodeCert.NA_x0008.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0004.value) == DVSGlobalStatusCodeCert.NA_x0004.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0002.value) == DVSGlobalStatusCodeCert.NA_x0002.value
        or (leCode & DVSGlobalStatusCodeCert.NA_x0001.value) == DVSGlobalStatusCodeCert.NA_x0001.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))

    return response


def DVSGlobalStatusSign(leCode):
    response = []
    if leCode is None:
        return response


    if ((leCode & DVSGlobalStatusCodeSign.INVALID_SIGNATURE.value) == DVSGlobalStatusCodeSign.INVALID_SIGNATURE.value):
        response.append((TypeReponse.ERREUR, "Au moins une signature est invalide"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Toutes les signatures sont valides (tous les contrôles effectués ont retournés le résultats attendu)"))

    if ((leCode & DVSGlobalStatusCodeSign.CRL_UPDATE_ERROR.value) == DVSGlobalStatusCodeSign.CRL_UPDATE_ERROR.value):
        response.append((TypeReponse.ERREUR, "Mise à jour des CRLs impossible"))
    else:
        response.append(
            (TypeReponse.SUCCES, "Mise à jour des CRLs forcée avant exécution ou mise à jour non demandée"))

    if ((leCode & DVSGlobalStatusCodeSign.NA_x8000.value) == DVSGlobalStatusCodeSign.NA_x8000.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0800.value) == DVSGlobalStatusCodeSign.NA_x0800.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0400.value) == DVSGlobalStatusCodeSign.NA_x0400.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0200.value) == DVSGlobalStatusCodeSign.NA_x0200.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0100.value) == DVSGlobalStatusCodeSign.NA_x0100.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0080.value) == DVSGlobalStatusCodeSign.NA_x0080.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0040.value) == DVSGlobalStatusCodeSign.NA_x0040.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0020.value) == DVSGlobalStatusCodeSign.NA_x0020.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0010.value) == DVSGlobalStatusCodeSign.NA_x0010.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0008.value) == DVSGlobalStatusCodeSign.NA_x0008.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0004.value) == DVSGlobalStatusCodeSign.NA_x0004.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0002.value) == DVSGlobalStatusCodeSign.NA_x0002.value
        or (leCode & DVSGlobalStatusCodeSign.NA_x0001.value) == DVSGlobalStatusCodeSign.NA_x0001.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))

    return response


def DVSStatusSign(detailedStatus):
    response = []
    if detailedStatus is None:
        return response


    if ((detailedStatus & DVSStatusCodeSign.VERIFICATION_ERROR.value) == DVSStatusCodeSign.VERIFICATION_ERROR.value):
        response.append((TypeReponse.ERREUR,
                         "Au moins un des contrôles effectué n'a pas retourné le résultat attendu"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Tous les contrôles effectués sur la signature et le certificat du signataire ont retourné le résultat attendu"))

    if ((detailedStatus & DVSStatusCodeSign.CERTIFICAT_EXPIRE.value) == DVSStatusCodeSign.CERTIFICAT_EXPIRE.value):
        response.append((TypeReponse.ERREUR, "Certificat de signature en dehors de sa période de validité"))
    else:
        response.append((TypeReponse.SUCCES, "Certificat de signature en cours de validité"))

    if ((
                    detailedStatus & DVSStatusCodeSign.CERTIFICAT_NOT_LISTED.value) == DVSStatusCodeSign.CERTIFICAT_NOT_LISTED.value):
        response.append((TypeReponse.ERREUR, "Le certificat n'est pas trouvé dans la liste blanche/noire"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Le certificat est trouvé dans la liste blanche/noire de certificats (ou aucune liste n'est configurée)"))

    if ((
                    detailedStatus & DVSStatusCodeSign.CERTIFICAT_DN_NOT_LISTED.value) == DVSStatusCodeSign.CERTIFICAT_DN_NOT_LISTED.value):
        response.append((TypeReponse.ERREUR, "Le DN du certificat n'est pas trouvé dans la liste blanche/noire"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Le DN du certificat est trouvé dans la liste blanche/noire (ou aucune liste de DN n'est configurée)"))

    if ((
                    detailedStatus & DVSStatusCodeSign.KEY_USAGE_NOT_COMPLIANT.value) == DVSStatusCodeSign.KEY_USAGE_NOT_COMPLIANT.value):
        response.append((TypeReponse.ERREUR, "Usage de la clé non conforme"))
    else:
        response.append((TypeReponse.SUCCES, "Usage de la clé conforme (ou non spécifiées)"))

    if ((detailedStatus & DVSStatusCodeSign.OID_NON_AUTORISE.value) == DVSStatusCodeSign.OID_NON_AUTORISE.value):
        response.append((TypeReponse.ERREUR, "OID de la Politique de Certification non référencée"))
    else:
        response.append((TypeReponse.SUCCES,
                         "OID de la Politique de Certification référencée (ou non spécifiées)"))

    if ((
                    detailedStatus & DVSStatusCodeSign.QCSTATEMENTS_NOT_COMPLIANT.value) == DVSStatusCodeSign.QCSTATEMENTS_NOT_COMPLIANT.value):
        response.append((TypeReponse.ERREUR, "Extensions QCStatements non conformes"))
    else:
        response.append((TypeReponse.SUCCES, "Extensions QCStatements conformes (ou non spécifiées)"))

    if ((
                    detailedStatus & DVSStatusCodeSign.BUSINESS_CRL_INVALID.value) == DVSStatusCodeSign.BUSINESS_CRL_INVALID.value):
        response.append((TypeReponse.ERREUR, "Validation métier d\'une CRL non valide"))
    else:
        response.append((TypeReponse.SUCCES, "Validation métier d\'une CRL valide (ou non paramétrée)"))

    if ((detailedStatus & DVSStatusCodeSign.ALGORITHME_INTERDIT.value) == DVSStatusCodeSign.ALGORITHME_INTERDIT.value):
        response.append((TypeReponse.ERREUR, "Algorithme interdit"))
    else:
        response.append((TypeReponse.SUCCES, "Algorithme conforme"))

    if ((detailedStatus & DVSStatusCodeSign.NA_x00000040.value) == DVSStatusCodeSign.NA_x00000040.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))

    if ((detailedStatus & DVSStatusCodeSign.AC_HORS_VALIDITE.value) == DVSStatusCodeSign.AC_HORS_VALIDITE.value):
        response.append((TypeReponse.ERREUR, "AC en dehors de sa période de validité"))
    elif ((
                      detailedStatus & DVSStatusCodeSign.AC_DONNEES_VALIDATION_MANQUANTE.value) == DVSStatusCodeSign.AC_DONNEES_VALIDATION_MANQUANTE.value):
        response.append((TypeReponse.ERREUR, "Données de validation manquantes"))
    elif ((detailedStatus & DVSStatusCodeSign.AC_REVOQUEE.value) == DVSStatusCodeSign.AC_REVOQUEE.value):
        response.append((TypeReponse.ERREUR, "Au moins une AC révoquée"))
    else:
        response.append((TypeReponse.SUCCES, "La chaîne est valide"))

    if ((detailedStatus & DVSStatusCodeSign.VALIDATION_OCSP_NA.value) == DVSStatusCodeSign.VALIDATION_OCSP_NA.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))
    elif ((
                      detailedStatus & DVSStatusCodeSign.VALIDATION_OCSP_DISPONIBLE.value) == DVSStatusCodeSign.VALIDATION_OCSP_DISPONIBLE.value):
        response.append((TypeReponse.SUCCES, "OCSP dès que disponible"))
    elif ((
                      detailedStatus & DVSStatusCodeSign.VALIDATION_OCSP_CERT.value) == DVSStatusCodeSign.VALIDATION_OCSP_CERT.value):
        response.append((TypeReponse.SUCCES, "OCSP pour le certificat de sinature"))
    else:
        response.append((TypeReponse.SUCCES, "CRL et ARL pour toute la chaîne"))

    if ((
                    detailedStatus & DVSStatusCodeSign.CERTIFICAT_AC_NON_AUTORISE.value) == DVSStatusCodeSign.CERTIFICAT_AC_NON_AUTORISE.value):
        response.append((TypeReponse.ERREUR, "AC émettrice non référencée"))
    elif ((
                      detailedStatus & DVSStatusCodeSign.CERTIFICAT_DONNEES_VALIDATION_MANQUANTE.value) == DVSStatusCodeSign.CERTIFICAT_DONNEES_VALIDATION_MANQUANTE.value):
        response.append((TypeReponse.ERREUR, "Données de validation manquantes"))
    elif ((detailedStatus & DVSStatusCodeSign.CERTIFICAT_REVOQUE.value) == DVSStatusCodeSign.CERTIFICAT_REVOQUE.value):
        response.append((TypeReponse.ERREUR, "Certificat révoqué"))
    else:
        response.append((TypeReponse.SUCCES, "Certificat valide"))

    if ((detailedStatus & DVSStatusCodeSign.HORODATE_IMPOSSIBLE.value) == DVSStatusCodeSign.HORODATE_IMPOSSIBLE.value):
        response.append((TypeReponse.ERREUR, "Horodatage de réception de la signature impossible"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Horodatage de réception de la signature effectué (ou non demandé)"))

    if ((detailedStatus & DVSStatusCodeSign.DOC_SEMANTIC_NA.value) == DVSStatusCodeSign.DOC_SEMANTIC_NA.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))
    elif ((
                      detailedStatus & DVSStatusCodeSign.DOC_SEMANTIC_IMPOSSIBLE.value) == DVSStatusCodeSign.DOC_SEMANTIC_IMPOSSIBLE.value):
        response.append((TypeReponse.ERREUR, "Vérification de la stabilité sémantique du document impossible"))
    elif ((
                      detailedStatus & DVSStatusCodeSign.DOC_SEMANTIC_INSTABLE.value) == DVSStatusCodeSign.DOC_SEMANTIC_INSTABLE.value):
        response.append((TypeReponse.ERREUR, "Stabilité sémantique du document: instable"))
    else:
        response.append((TypeReponse.SUCCES, "Stabilité sémantique du document: stable (ou non demandé)"))

    if ((
                    detailedStatus & DVSStatusCodeSign.SIGNATURE_INCOMPLIANT.value) == DVSStatusCodeSign.SIGNATURE_INCOMPLIANT.value):
        response.append((TypeReponse.ERREUR, "Propriétés de la signatures non-conformes"))
    else:
        response.append((TypeReponse.SUCCES, "Propriétés de la signatures conformes (ou non spécifiées)"))

    if ((detailedStatus & DVSStatusCodeSign.SIGNATURE_INVALID.value) == DVSStatusCodeSign.SIGNATURE_INVALID.value):
        response.append((TypeReponse.ERREUR, "Signature cryptographique invalide"))
    else:
        response.append((TypeReponse.SUCCES, "Signature cryptographique valide"))

    if ((detailedStatus & DVSStatusCodeSign.TEMPORAL_WINDOW_OUT.value) == DVSStatusCodeSign.TEMPORAL_WINDOW_OUT.value):
        response.append((TypeReponse.ERREUR, "En dehors de la fenêtre temporelle (non implémenté)"))
    else:
        response.append((TypeReponse.SUCCES, "Fenêtre temporelle respectée (non implémenté)"))

    if ((detailedStatus & DVSStatusCodeSign.HORODATAGE_INVALID.value) == DVSStatusCodeSign.HORODATAGE_INVALID.value):
        response.append((TypeReponse.ERREUR, "Jeton d\'horodatage de la signature invalide"))
    else:
        response.append((TypeReponse.SUCCES, "Jeton d\'horodatage de la signature valide"))

    if ((detailedStatus & DVSStatusCodeSign.REFERENCE_NOT_FOUND.value) == DVSStatusCodeSign.REFERENCE_NOT_FOUND.value):
        response.append((TypeReponse.ERREUR, "Référence introuvable lors de la résolution des références"))
    else:
        response.append((TypeReponse.SUCCES, "Succès de la résolution des références"))

    if ((detailedStatus & DVSStatusCodeSign.ADES_REF_INCOHERENT.value) == DVSStatusCodeSign.ADES_REF_INCOHERENT.value):
        response.append((TypeReponse.ERREUR,
                         "Incohérence entre les références (AdES-C) et les valeurs (AdES-L) des données de validation d\'une signature AdES-A (les références ne correspondent pas aux valeurs)"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Cohérence entre les références (AdES-C) et les valeurs (AdES-L) des données de validation d\'une signature AdES-A"))

    if ((
                    detailedStatus & DVSStatusCodeSign.XADES_ATTRIBUTE_NOT_FOUND.value) == DVSStatusCodeSign.XADES_ATTRIBUTE_NOT_FOUND.value):
        response.append((TypeReponse.ERREUR, "Attribut XAdES non supportés touvés"))
    else:
        response.append((TypeReponse.SUCCES, "Succès de la validation des attibuts XAdES"))

    if ((detailedStatus & DVSStatusCodeSign.NA_x00000020.value) == DVSStatusCodeSign.NA_x00000020.value
        or (detailedStatus & DVSStatusCodeSign.NA_x00000020.value) == DVSStatusCodeSign.NA_x00000020.value
        or (detailedStatus & DVSStatusCodeSign.NA_x00000010.value) == DVSStatusCodeSign.NA_x00000010.value
        or (detailedStatus & DVSStatusCodeSign.NA_x00000008.value) == DVSStatusCodeSign.NA_x00000008.value
        or (detailedStatus & DVSStatusCodeSign.NA_x00000004.value) == DVSStatusCodeSign.NA_x00000004.value
        or (detailedStatus & DVSStatusCodeSign.NA_x00000002.value) == DVSStatusCodeSign.NA_x00000002.value
        or (detailedStatus & DVSStatusCodeSign.NA_x00000001.value) == DVSStatusCodeSign.NA_x00000001.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))

    return response


def DVSStatusCert(detailedStatus):
    response = []
    if detailedStatus is None:
        return response

    if ((
                    detailedStatus & DVSStatusCodeCert.CERTIFICAT_AC_NON_AUTORISE.value) == DVSStatusCodeCert.CERTIFICAT_AC_NON_AUTORISE.value):
        response.append((TypeReponse.ERREUR, "AC émettrice non référencée"))
    elif ((
                      detailedStatus & DVSStatusCodeCert.CERTIFICAT_DONNEES_VALIDATION_MANQUANTE.value) == DVSStatusCodeCert.CERTIFICAT_DONNEES_VALIDATION_MANQUANTE.value):
        response.append((TypeReponse.ERREUR, "Données de validation manquantes"))
    elif ((detailedStatus & DVSStatusCodeCert.CERTIFICAT_REVOQUE.value) == DVSStatusCodeCert.CERTIFICAT_REVOQUE.value):
        response.append((TypeReponse.ERREUR, "Certificat révoqué"))
    else:
        response.append((TypeReponse.SUCCES, "Certificat valide"))

    if ((detailedStatus & DVSStatusCodeCert.NA_x000C.value) == DVSStatusCodeCert.NA_x000C.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))
    elif ((
                      detailedStatus & DVSStatusCodeCert.VALIDATION_OCSP_DISPONIBLE.value) == DVSStatusCodeCert.VALIDATION_OCSP_DISPONIBLE.value):
        response.append((TypeReponse.SUCCES, "OCSP dès que disponible"))
    elif ((
                      detailedStatus & DVSStatusCodeCert.VALIDATION_OCSP_CERT.value) == DVSStatusCodeCert.VALIDATION_OCSP_CERT.value):
        response.append((TypeReponse.SUCCES, "OCSP pour le certificat de sinature"))
    else:
        response.append((TypeReponse.SUCCES, "CRL et ARL pour toute la chaîne"))

    if ((detailedStatus & 3) == 3):
        response.append((TypeReponse.ERREUR, "AC en dehors de sa période de validité"))
    elif ((detailedStatus & 3) == 2):
        response.append((TypeReponse.ERREUR, "Données de validation manquantes"))
    elif ((detailedStatus & 3) == 1):
        response.append((TypeReponse.ERREUR, "Au moins une AC révoquée"))
    else:
        response.append((TypeReponse.SUCCES, "La chaîne est valide"))

    if ((detailedStatus & DVSStatusCodeCert.ALGORITHME_INTERDIT.value) == DVSStatusCodeCert.ALGORITHME_INTERDIT.value):
        response.append((TypeReponse.ERREUR, "Algorithme interdit"))
    else:
        response.append((TypeReponse.SUCCES, "Algorithme conforme"))

    if ((
                    detailedStatus & DVSStatusCodeCert.BUSINESS_CRL_INVALID.value) == DVSStatusCodeCert.BUSINESS_CRL_INVALID.value):
        response.append((TypeReponse.ERREUR, "Validation métier d\'une CRL non valide"))
    else:
        response.append((TypeReponse.SUCCES, "Validation métier d\'une CRL valide (ou non paramétrée)"))

    if ((
                    detailedStatus & DVSStatusCodeCert.QCSTATEMENTS_NOT_COMPLIANT.value) == DVSStatusCodeCert.QCSTATEMENTS_NOT_COMPLIANT.value):
        response.append((TypeReponse.ERREUR, "Extensions QCStatements non conformes"))
    else:
        response.append((TypeReponse.SUCCES, "Extensions QCStatements conformes (ou non spécifiées)"))

    if ((detailedStatus & DVSStatusCodeCert.OID_NON_AUTORISE.value) == DVSStatusCodeCert.OID_NON_AUTORISE.value):
        response.append((TypeReponse.ERREUR, "OID de la Politique de Certification non référencée"))
    else:
        response.append((TypeReponse.SUCCES, "OID de la Politique de Certification référencée (ou non spécifiées)"))

    if ((
                    detailedStatus & DVSStatusCodeCert.KEY_USAGE_NOT_COMPLIANT.value) == DVSStatusCodeCert.KEY_USAGE_NOT_COMPLIANT.value):
        response.append((TypeReponse.ERREUR, "Usage de la clé non conforme"))
    else:
        response.append((TypeReponse.SUCCES, "Usage de la clé conforme (ou non spécifiées)"))

    if ((
                    detailedStatus & DVSStatusCodeCert.CERTIFICAT_DN_NOT_LISTED.value) == DVSStatusCodeCert.CERTIFICAT_DN_NOT_LISTED.value):
        response.append((TypeReponse.ERREUR, "Le DN du certificat n'est pas trouvé dans la liste blanche"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Le DN du certificat est trouvé dans la liste blanche (ou aucune liste de DN n'est configurée)"))

    if ((
                    detailedStatus & DVSStatusCodeCert.CERTIFICAT_NOT_LISTED.value) == DVSStatusCodeCert.CERTIFICAT_NOT_LISTED.value):
        response.append((TypeReponse.ERREUR, "Le certificat n'est pas trouvé dans la liste blanche"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Le certificat est trouvé dans la liste blanche de certificats (ou aucune liste n'est configurée)"))

    if ((detailedStatus & DVSStatusCodeCert.CERTIFICAT_EXPIRE.value) == DVSStatusCodeCert.CERTIFICAT_EXPIRE.value):
        response.append((TypeReponse.ERREUR, "Certificat de signature en dehors de sa période de validité"))
    else:
        response.append((TypeReponse.SUCCES, "Certificat de signature en cours de validité"))

    if ((detailedStatus & DVSStatusCodeCert.CERTIFICATE_INVALID.value) == DVSStatusCodeCert.CERTIFICATE_INVALID.value):
        response.append((TypeReponse.ERREUR, "Le certificat est invalide"))
    else:
        response.append((TypeReponse.SUCCES,
                         "Le certificat est valide (tous les contrôles effectués ont retournés le résultat attendu)"))

    if ((detailedStatus & DVSStatusCodeCert.NA_x0040.value) == DVSStatusCodeCert.NA_x0040.value
        or (detailedStatus & DVSStatusCodeCert.NA_x0020.value) == DVSStatusCodeCert.NA_x0020.value
        or (detailedStatus & DVSStatusCodeCert.NA_x0010.value) == DVSStatusCodeCert.NA_x0010.value):
        response.append((TypeReponse.ERREUR, "Erreur normalement non attribué"))

    return response


if __name__ == "__main__":
    try:

        parser = argparse.ArgumentParser(description='DVS caller.')
        parser.add_argument('mode', metavar='--mode', type=str, help='CERT or SIGN')
        parser.add_argument('opStatus', metavar='--opStatus', type=int, help='opStatus')
        parser.add_argument('--globalStatus', metavar='-gStatus', type=int, help='globalStatus')
        parser.add_argument('--detailedStatus', metavar='-dStatus', type=int, help='detailedStatus')

        args = parser.parse_args()

        print 'OpStatus \t:', args.opStatus
        print pprint(OpStatus(args.opStatus))

        if args.globalStatus is not None:
            if args.mode == 'CERT':
                dvs_global_status = DVSGlobalStatusCert(args.globalStatus)
            else:
                dvs_global_status = DVSGlobalStatusSign(args.globalStatus)

            print 'DVSGlobalStatus\t:', args.globalStatus
            print pprint(dvs_global_status)

        if args.detailedStatus is not None:
            if args.mode == 'CERT':
                dvs_status = DVSStatusCert(args.detailedStatus)
            else:
                dvs_status = DVSStatusSign(args.detailedStatus)

            print "DVSStatus \t:", args.detailedStatus
            print pprint(dvs_status)

    except Exception as e:
        print e
        traceback.print_exc(file=sys.stdout)
        sys.exit(3)
