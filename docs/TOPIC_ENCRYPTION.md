# Documentation : Chiffrement de Topic IRC avec FiSH-11

## Vue d'Ensemble

Le module FiSH-11 prend en charge deux méthodes de chiffrement pour les topics IRC :

1. **Chiffrement manuel** : Utilise une clé partagée préalablement échangée entre utilisateurs
2. **Chiffrement FCEP-1** : Utilise une clé de canal partagée entre plusieurs membres avec ratcheting (Forward Secrecy)

## Méthode 1 : Chiffrement de Topic Manuel

### Procédure

1. Échangez une clé avec un utilisateur via `/fish11_X25519_INIT <pseudo>`
2. Une fois la clé établie, vous pouvez chiffrer un topic pour ce canal comme pour n'importe quel message

### Fonctionnement Technique

Lorsque l'utilisateur tape `/etopic #canal <message>` dans mIRC :

1. Le script détecte que c'est un topic pour un canal
2. Il appelle la DLL avec `FiSH11_EncryptMsg("#canal", "<message>")`  
3. La DLL détecte que la cible est un canal (`#` ou `&`)
4. Elle récupère la clé de canal (soit de FCEP-1, soit manuelle)
5. Elle chiffre le message avec la clé appropriée
6. Le message chiffré est envoyé au format `+FiSH <donnees_chiffrees>`

## Méthode 2 : Chiffrement de Topic FCEP-1

### Procédure

1. Initialisez le canal FCEP-1 avec `/fish11_initchannel #canal <membre1> <membre2> ...`
2. Le coordinateur distribue la clé de canal aux membres via leurs clés pré-partagées
3. Quand un topic est défini sur ce canal, il est automatiquement chiffré avec la clé de canal

### Fonctionnement Technique

Le chiffrement de topic FCEP-1 utilise le même mécanisme que les messages de canal :

- Utilise le système de ratchet symétrique pour Forward Secrecy
- La clé est dérivée via HKDF-SHA256
- Le nom du canal est inclus comme Associated Data (AD) pour empêcher les attaques de type cross-channel replay
- Le ratchet avance après chaque message (y compris les topics)

## Gestion des Clés

### Stockage

- Les topics manuels utilisent la même clé que les messages privés : `nickname@network`
- Les topics FCEP-1 utilisent la clé de canal : `#canal@network`
- Les noms sont normalisés en minuscules pour la cohérence

### Formats

Pour les topics FCEP-1, les messages sont envoyés au format spécial :
```
NOTICE <membre> :+FiSH-CEP-KEY <#canal> <coordinateur> <clé_encapsulée>
```

Pour les topics chiffrés dans les canaux :
- `PRIVMSG #canal :+FiSH <topic_chiffré>` (pour affichage)
- Le serveur traite le `/TOPIC` normalement mais le contenu est chiffré

## Commandes Disponibles

### Commandes Utilisateur

1. **`/etopic <#canal> <topic>`** : Chiffre et envoie un topic
2. **`/fish11_initchannel <#canal> <membre>...`** : Initialise un canal FCEP-1
3. **Menu contextuel** : "Set topic (encrypted)" dans les menus de canal

### Gestion des Canaux

- **`/fish11_listchannelkeys`** : Lister les clés de canal
- **`/fish11_removechankey <#canal>`** : Supprimer la clé d'un canal
- **`/fish11_showchankey <#canal>`** : Afficher la clé de canal (base64)

## Compatibilité Multi-Réseaux

Le système supporte la connexion à plusieurs serveurs IRC :
- Les clés sont stockées avec le format `cible@reseau`
- Le réseau est détecté automatiquement via les messages IRC 005 (NETWORK=)
- Le contexte réseau est mis à jour automatiquement avant chaque opération

## Sécurité Renforcée

- **Authentification du sender** : Vérifie que l'expéditeur est bien le coordinateur déclaré
- **Anti-replay protection** : Nonce cache pour chaque canal
- **Cross-channel protection** : Binding du nom de canal comme Associated Data
- **Forward Secrecy** : Pour FCEP-1 via ratcheting symétrique
- **Post-Compromise Security** : Récupération automatique après compromission

## Résolution des Problèmes

### Dépannage des Topics

1. **Vérifiez l'existence d'une clé** : Utilisez `/fish11_showkey #canal` ou `/fish11_file_list_keys`
2. **Vérifiez le format du canal** : Doit commencer par `#` ou `&` et être conforme à RFC 2812
3. **Vérifiez la synchronisation réseau** : Assurez-vous que le réseau est correctement détecté
4. **Consultez les logs** : Activez le mode debug pour voir les détails des opérations

### Messages d'Erreur Courants

- `"Key not found"` : Aucune clé établie pour ce canal/utilisateur
- `"Invalid channel name"` : Format de canal incorrect
- `"Sender mismatch"` : Attaque d'impersonation détectée
- `"Replay attack detected"` : Message déjà reçu avec ce nonce

## Configuration

Le système lit/écrit dans `fish_11.ini` :

```ini
[#canal@EFNet]
key=clé_base64_encodée...
date=date_de_création...

[channel_ratchet_state]
#canal@EFNet=current_epoch:clé_actuelle:clé_précédente...

[networks]
#canal=EFNet
```

## Limitations et Remarques

- Les anciens topics non chiffrés restent non chiffrés
- Les membres sans clé pré-partagée ne peuvent pas participer à FCEP-1
- Le ratchet maintient une fenêtre de clés pour tolérer les messages hors ordre
- La taille maximale des topics est limitée par les contraintes IRC (~400-500 chars)

## API DLL

Les fonctions importantes pour le chiffrement de topic sont :

- `FiSH11_EncryptMsg(target, message)` - Gère le chiffrement pour canaux/messages privés
- `FiSH11_DecryptMsg(target, encrypted)` - Gère le déchiffrement
- `FiSH11_InitChannelKey` - Initialise une clé de canal FCEP-1
- `FiSH11_ProcessChannelKey` - Traite une clé de canal reçue
- `FiSH11_FileListKeys` - Liste toutes les clés (y compris de canal)

## Bonnes Pratiques de Sécurité

1. **Vérifiez les empreintes** : Utilisez `/fish11_showfingerprint <pseudo>` après l'échange de clé
2. **Vérifiez manuellement** : Confirmez visuellement la présence de `+FiSH` dans les topics
3. **Rotation régulière** : Réinitialisez les clés de canal périodiquement
4. **Surveillance** : Surveillez les messages d'erreur de sécurité dans les logs