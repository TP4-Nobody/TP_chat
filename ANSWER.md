# Réponses aux questions

## Prise en main

### Question 1

Cette typology est appelée "client server" ou "étoile".

### Question 2

On remarque dans les logs du serveur que le message envoyé entre les clients ne sont pas chiffrés. On peut donc les intercepter et les lire. On peut aussi modifier le message avec une attaque. Par exemple avec l'attaque de l'homme du milieu.

### Question 3

Cela pose problème car le message peut être intercepté, lu et modifié sans que l'on ne le sache. Cela peut être dangereux pour les données sensibles. Cela viole le principe de confidentialité.

### Question 4

La façon la plus simple de résoudre ce problème est de chiffrer le message avec une clé symétrique. Après ça, on envoye cette clé chiffrée avec la clé publique du destinataire. Le destinataire pourra donc déchiffrer le message.

## Chiffrement

### Question 1


