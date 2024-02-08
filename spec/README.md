# Quelques notes à proprifier

1. Concaténer les fichiers
`swagger-cli bundle -o onefile.yml capsule-api/index.yml`

2. Serveur mock
`sudo docker run -p 8000:8000 -v -d $PWD/onefile.yml:/api.yml danielgtaylor/apisprout /api.yml`

3. Documentation en ligne
`sudo docker run -d -p 8080:8080 -e BASE_URL=/ui -e SWAGGER_JSON=/api.json -v $PWD/onefile.yml:/api.json swaggerapi/swagger-ui`

Attention, il y a un pb avec l'unité "GB" dans les quotas, une solution est à trouver.
Attention bis, il faut renseigner la bonne url dans le `onefile.yml` afin que l'`ui` swagger puisse discuter avec le serveur mock.

Note : `apisprout` gère pas mal de choses, voir la [doc ici](https://github.com/danielgtaylor/apisprout).
