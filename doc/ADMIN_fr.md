L'interface est protégée par permission :
`yunohost user permission update anubis.admin --add <utilisateur|groupe>`.

Les politiques sont dans `/etc/anubis/policy.yaml` (gérées) ; après édition
manuelle, relancez `systemctl restart anubis`. Si Anubis tombe, les requêtes
passent (fail open) par conception.
