# Bearer Proxy

Proxy HTTP local (Python 3, **stdlib uniquement**, aucune dépendance) qui transmet vos requêtes
vers une API cible en ajoutant automatiquement l'en-tête `Authorization: Bearer <token>`.
Le token est obtenu via OAuth2, mis en cache, rafraîchi avant expiration, et renégocié
automatiquement si l'API renvoie un `401`.

## Lancement

```bash
cp .env.example .env      # puis éditez .env avec vos valeurs
python3 proxy.py
```

Le proxy écoute par défaut sur `http://127.0.0.1:8080` et transmet tout vers `UPSTREAM_URL` :

```bash
curl http://127.0.0.1:8080/v1/ressources
# → GET https://api.example.com/v1/ressources avec Authorization: Bearer <token>
```

## Configuration (variables d'environnement ou fichier `.env`)

| Variable | Description |
|---|---|
| `UPSTREAM_URL` | URL de base de l'API cible (ex. `https://api.example.com`) |
| `OAUTH_TOKEN_URL` | Endpoint du token OAuth2 (ex. `https://auth.example.com/oauth/token`) |
| `OAUTH_CLIENT_ID` | Client id OAuth2 |
| `OAUTH_CLIENT_SECRET` | Client secret OAuth2 |
| `OAUTH_SCOPE` | Scopes optionnels, séparés par des espaces |
| `OAUTH_REFRESH_TOKEN` | Optionnel : utilise le grant `refresh_token` au lieu de `client_credentials` |
| `OAUTH_AUTH_METHOD` | `body` (défaut) ou `basic` selon ce qu'exige le serveur OAuth2 |
| `BIND_HOST` | Adresse d'écoute, défaut `127.0.0.1` |
| `PORT` | Port d'écoute, défaut `8080` |
| `UPSTREAM_TIMEOUT` | Timeout vers l'API en secondes, défaut `60` |

## Fonctionnement

- Tous les chemins sont transmis tels quels : `http://127.0.0.1:8080/foo/bar` → `UPSTREAM_URL/foo/bar`.
- Méthodes supportées : GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS (corps et query string inclus).
- Les en-têtes hop-by-hop (`Connection`, `Transfer-Encoding`, `Host`, etc.) sont retirés.
- Token mis en cache et renouvelé 60 s avant `expires_in` ; sur `401` de l'API, le token est
  renégocié et la requête est rejouée une seule fois.
- Erreur joignable vers l'API → réponse `502`.

## Sécurité

- Le proxy n'écoute que sur `127.0.0.1` par défaut : il n'est pas accessible depuis le réseau.
  Ne mettez pas `BIND_HOST=0.0.0.0` sans ajouter une authentification devant le proxy.
- Ne commitez jamais le fichier `.env` (ajoutez-le au `.gitignore`).

## Tests

```bash
python3 -m unittest test_proxy.py -v
```

Les tests simulent un serveur OAuth2 et une API cible en local et vérifient l'injection du token,
la transmission du corps POST, le retry sur 401 et la réponse 502.
