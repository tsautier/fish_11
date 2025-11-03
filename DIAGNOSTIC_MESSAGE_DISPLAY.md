# Diagnostic : Message déchiffré mais pas affiché

## Symptôme
- CLIENT A envoie un message chiffré "+FiSH QLXPe..."
- CLIENT B reçoit le message, l'engine le déchiffre correctement en "TEST02"
- Les logs montrent : `After: :bobssl!~bobssl@waf.w00.wf PRIVMSG bobclient :TEST02`
- Le buffer processed_incoming contient 52 bytes
- **MAIS** le message ne s'affiche pas dans mIRC du CLIENT B

## Analyse
Le log montre que :
1. ✅ Le message est reçu (102 bytes)
2. ✅ L'engine déchiffre correctement (Before: +FiSH... → After: TEST02)
3. ✅ Le buffer processed_incoming est rempli (52 bytes)
4. ❓ Ce qui est retourné à mIRC n'est PAS loggé

## Hypothèses possibles

### Hypothèse 1 : Le buffer n'est pas correctement retourné
- Le code appelle `socket_info.get_processed_buffer()` 
- Puis copie dans `buf` avec `copy_from_slice`
- Mais peut-être que la taille retournée (`bytes_to_copy`) est 0 ?
- **FIX AJOUTÉ** : logs debug pour tracer exactement ce qui est retourné

### Hypothèse 2 : mIRC reçoit le bon buffer mais ne l'affiche pas
- Possible si le format IRC est incorrect
- Possible si mIRC filtre les messages sans handler
- Le script fish_11.mrc n'a PAS de handler `on *:TEXT:` pour les messages normaux

### Hypothèse 3 : Le message nécessite \r\n
- Le buffer déchiffré contient-il bien `\r\n` à la fin ?
- IRC requiert `\r\n` pour délimiter les lignes

## Prochaines étapes

1. **Rebuild avec nouveaux logs**
   ```powershell
   .\rebuild_and_test.ps1
   ```

2. **Tester dans mIRC**
   - Redémarrer mIRC
   - Refaire l'échange de clés : `/fish11_X25519_INIT bobclient`
   - Envoyer un message depuis CLIENT A
   - Observer CLIENT B

3. **Analyser les nouveaux logs**
   Chercher dans les logs inject :
   ```
   [RECV DEBUG] Socket XXX: returning Y bytes to mIRC
   [RECV DEBUG] Socket XXX: returning to mIRC: "..."
   ```

4. **Si bytes_to_copy == 0**
   → Le buffer processed_incoming n'est pas rempli correctement

5. **Si le message est retourné mais pas affiché**
   → Vérifier le format (doit avoir \r\n)
   → Ajouter un handler dans fish_11.mrc si nécessaire

## Format attendu
Le message retourné à mIRC DOIT être :
```
:bobssl!~bobssl@waf.w00.wf PRIVMSG bobclient :TEST02\r\n
```
- Prefix complet (`:nick!user@host`)
- Commande IRC (`PRIVMSG`)
- Target (`bobclient`)
- Message (`:TEST02`)
- Terminé par `\r\n`

Si le format est correct, mIRC devrait l'afficher automatiquement.
