Anubis est un bouclier anti-bot à preuve de travail qui se place devant vos
domaines YunoHost. Les robots reçoivent un défi JavaScript avant d'atteindre vos
applications (ou même la page de connexion SSO) ; les vrais visiteurs ne le
résolvent qu'une fois et reçoivent un cookie.

Ce paquet exécute le binaire Go en amont nativement (sans Docker) et ajoute une
petite interface web, accessible depuis le portail YunoHost, où vous cochez
exactement quels domaines/sous-domaines doivent être protégés.
