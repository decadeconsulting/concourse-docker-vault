# Concourse Docker with vault secrets store

forked of the [offical concourse docker repo](https://github.com/concourse/concourse-docker)

The Docker image just packages up the official `concourse` binary and configures it as the `ENTRYPOINT`, with a bunch of sane defaults for Docker. This fork did not change anything to the docker image setup.

### TL;DR

```
make setup

make dockerup

(wait for containers to come up)

make unseal

make test

(if fails, try to docker restart concourse-docker-vault_web_1</br>
 and
 for i in {1..3} ; do vault operator unseal ; done)

http://localhost:8080
```

## Running with `docker-compose`

Use the `Makefile` to get up and running and also as source of information on how to do things manually.

### fresh initial setup

Use `make setup` to generate concourse session_signing_key, tsa_host_key and worker_key (via `keys/generate` script) </br>
as well as a self signed rootCA and a vault and concourse certificate signed by that rootCA (via `./createCertificate.sh`).

keys will be generated to `./keys` subfolders (`./keys/vault` will contain the vault unseal information later on)</br>
certs will be generated to `./certs`

These folders will also be mounted into the corresponding docker containers via the `./docker-compose.yml` file.

for initially unsealing the vault and setting corresponding policies afterwards you have to start the containers</br>
via either of `make dockerup` just `make` or `docker-compose up -d`

After docker containers are up, call `make unseal`</br>
which will ask you interactively for 3 of the 5 unseal keys. So copy and paste.

unseal information you see will be stored in plain text under `./keys/vault/vaultkeys.txt`

unseal vault_postsetup will enable a kv engine in vault under paht `/concourse`</br>
and define a vault policy file which is also (for convenience purposes not needing a second mount) under `./certs/vault/vault_concourse_policy.hcl`

**IMPORTANT!!**</br>
For changes on keys, certs and policies configuration to take effect restart the containers</br>
either with `make restart` or `docker-compose restart`

**IMPORTANT!!**</br>
on policy change the vault might be sealed again.

Use `vaul operator unseal` and the unseal keys ander `./keys/vault/vaultkeys.txt` to unseal it again.</br>
better `for i in {1..3} ; do vault operator unseal ; done`

### starting already existing images

Usually just running `make` or `make default` should be fine to go, or do `docker-ompose up -d`.

### stopping a running installation

`make dockerdown` or `docker-compose down` will stop all containers

### cleaning up / destroying an installation

`make clean` will delete all files under ./keys/** and ./certs/** (effectively all `.gitignore`d files)</br>
containers running will remain, but get unfunctional, please `docker rm -f <namesOrHashes>` these manually.



### Configuration

The default configuration sets up a `test` user with `test` as their password (see `CONCOURSE_ADD_LOCAL_USER` in `./docker-compose.yml`)
and grants them access (ownership) to `main` team. To use this in production you'll
definitely want to change that - see [Auth & Teams](https://concourse-ci.org/auth.html) for more information..

## vault authentication and authorisation

There are a multitude auf authentication methods possible with vault (see [https://www.vaultproject.io/docs/auth/](https://www.vaultproject.io/docs/auth/)).

Remember authentication and authorization are strictly separated in vault (via policies)

For a user/group/role like ***authorisation*** management, take a look at the tutorial [https://learn.hashicorp.com/vault/identity-access-management/iam-identity](https://learn.hashicorp.com/vault/identity-access-management/iam-identity)

### vault certificate based authentication

if cert based authentication was enabled with `vault auth enable cert` and vault configured accordingly</br>
a user can authenticate with a certificate that is signed by the rootca which is configured in vault.

user cert generation, e.g.:

`./createCertificate.sh --destfolder certs/manager --cafilebasename certs/rootca cert manager`

(certs CN can be anything, if just used for authentication for vault)

vault configuration for it:

```
vault write auth/cert/certs/manager \
			policies=manager \
			certificate=@certs/rootca.cert
```

login:

```
vault login -method=cert \
        -ca-cert=certs/rootca.cert \
        -client-cert=certs/manager/manager.cert \
        -client-key=certs/manager/manager.key \
        name=manager
```

The above requires Vault to present a certificate signed by rootca.cert and presents manager.cert (using manager.key) to authenticate against the manager cert role. Note that the name of 'manager' ties out with the configuration example below writing to a path of auth/cert/certs/manager. If a certificate role name is not specified, the auth method will try to authenticate against all trusted certificates.

### vault token based authentication

The token method is built-in and automatically available at /auth/token. It allows users to authenticate using a token, as well to create new tokens, revoke secrets by token, and more.

You can login with e.g. the root token that you got on first time unsealing vault

`vault login token=<rootToken>`

### vault user/pass based authentication

`vault auth enable userpass`

vault configuration for it:

```
vault write auth/userpass/users/manager \
			password=manager \
			policies=manager
```

login:

```
vault login -method=userpass \
    username=manager \
    password=manager
```

## concourse UI and fly cli

concourse UI should be reachable at [http://localhost:8080](http://localhost:8080)

fly cli login with e.g.:

`fly --target local login --concourse-url http://localhost:8080 -u test -p test`

## vault ui

[https://localhost:8200/ui](https://localhost:8200/ui)

you can login with the root token from `./keys/vault/vaultkeys.txt`

But it is highly recommended to create further policies and entities for making usage of vault beyond storing secrets for concourse pipelines.

In the as-is status quo only the root token is able to write anything to the vault.

## smoke test

```
fly -t local execute -c test/task_hello_world.yml
fly -t local execute -c test/task_hello_worldsecret.yml
```

or

`make test`

you shoudl see a `hello world` for the first and `testsecret:  Sun 16 Feb 2020 18:36:52 CET` for the second (obviously your current datetime).

## troubleshooting

If things seem to be going wrong, check the logs for any errors:

```sh
$ docker-compose logs -f
Attaching to concourse-docker_worker_1, concourse-docker_web_1, concourse-docker_db_1
...
```

On vault policy or configuration changes the vault might be sealed again.

Use `vaul operator unseal` and the unseal keys ander `./keys/vault/vaultkeys.txt` to unseal it again.

Furthermore after a vault policy or configuration change and a `make restart` or `docker restart`
the concourse-docker-vault_web_1 container might have come up before the vault container completely initialized and that might prevent the concourse-docker-vault_web_1 container to access a valid token or config.

In that case `docker restart concourse-docker-vault_web_1` once again.


## Running with `docker run`

Concourse components can also be run with regular old `docker run` commands.
Please use `docker-compose.yml` as the canonical reference for the necessary
flags/vars and connections between components. Further documentation on
configuring Concourse is available in the [Concourse Install
docs](https://concourse-ci.org/install.html).

## Building `concourse/concourse`

The `Dockerfile` in this repo is built as part of our CI process - as such, it
depends on having a pre-built `linux-rc` available in the working directory, and
ends up being published as `concourse/concourse` (by the originally forked off project: [https://github.com/concourse/concourse-docker](https://github.com/concourse/concourse-docker))
