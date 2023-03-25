# Réponses aux questions

## Prise en main

### Question 1

Cette typology est appelée "client server" ou "étoile".

### Question 2

On remarque dans les logs du serveur que le message envoyé entre les clients ne sont pas chiffrés. On peut donc les intercepter et les lire. On peut aussi modifier le message avec une attaque. Par exemple avec l'attaque de l'homme du milieu.

### Question 3

Cela pose problème car le message peut être intercepté, lu et modifié sans que l'on ne le sache. Cela peut être dangereux pour les données sensibles. Cela viole le principe de Kerckhoffs.

### Question 4

La façon la plus simple de résoudre ce problème est de chiffrer le message avec une clé symétrique. Après ça, on envoye cette clé chiffrée avec la clé publique du destinataire. Le destinataire pourra donc déchiffrer le message.

## Chiffrement

### Question 1

Le urandom est un bon choix pour de la cryptographie car il génére des nombres aléatoires en utilisant l'entropie du sytème ce qui en fait un générateur suffisamment fort pour qu'il soit difficile à prédire. Cependant, suivant les cas d'utilisation, il peut être nécessaire d'utiliser un générateur de nombres aléatoires plus robuste.

### Question 2

Ces primitives cryptographiques peuvent être dangereuses si elles sont mal utilisées, si elles présentent des failles de vulnérabilité car elles peuvent être utilisées pour des attaques.

### Question 3

Le chiffrement permet de rendre les données illisibles pour les clients non autorisés. Un serveur malveillant pourrait les modifiées car le chiffrement n'est pas fiable. Il est donc nécessaire de vérifier l'intégrité des données.

### Question 4

Il nous manque la vérification de l'intégrité des données. Pour cela, on peut utiliser un HMAC.

## Authenticated Symmetric Encryption

### Question 1

Parce que Fernet utilise un HMAC pour vérifier l'intégrité des données. AES ne le fait pas. Cela permet de s'assurer que les données n'ont pas été modifiées. Si les données ont été modifiées, le HMAC ne correspondra pas et le message ne pourra pas être déchiffré.

### Question 2

Cela s'appelle l'attaque de replays. Cela permet de réutiliser un message chiffré utilisé précédemment pour l'authentification et ainsi de le faire passer pour un utilisateur déjà authentifié. Par conséquent, cela permet de contourner l'authentification.

### Question 3

Pour éviter ce genre d'attaque, nous pouvons utiliser un temps de validité par message. Ainsi, le message ne sera plus valide après un certain temps.

## TTL

### Question 1

Oui maintenant il y a un temps de validité pour chaque message. Si le message est trop vieux, il ne sera pas déchiffré et une erreur sera visible dans les logs.

### Question 2

Quand on soustrait 45 secondes au TTL, on obtient une erreur de lors du déchiffrement. Parce que le TTL est dépassé et donc le message est considéré "trop vieux".

### Question 3

Cette méthode est efficace pour éviter les attaques de replays car elle permet de s'assurer que le message n'a pas été utilisé précédemment.

### Question 4

Cette méthode n'est pas fiable car le serveur peut être compromis et donc le temps peut être altéré pour permettre l'attaque de replays. Elle connait donc une faille de vulnérabilité.

## Autocritique

Mon code crash au moment de recevoir les messages quand nous prenons des mots de passe différents. Mais cela peut être résolu par un "try & except". Je m'en suis rendu compte qu'en faisant le time_fernet_gui.py. De plus, comme expliqué dans la question précédente, le serveur peut être compromis et le temps peut être altéré pour permettre l'attaque de replays. Il y a donc une faille de vulnérabilité. 
Pour éviter ce genre d'attaque, nous pouvons mettre en place un système d'authentification et de protection pour le serveur.