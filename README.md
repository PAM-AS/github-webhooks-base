# github-webhooks-base

A docker image to build upon that listens to github webhooks.

Credit and reference:

* Webhook listener based on [razius/github-webhook-handler](https://github.com/razius/github-webhook-handler/blob/master/index.py)
* Server and docker config based partially on [this article](https://www.digitalocean.com/community/tutorials/docker-explained-how-to-containerize-python-web-applications)

## Config

### Environment variables

Set a custom webhook port (default is `41414`)
```
WEBHOOKS_PORT=41414
```

Set environment variable for the repos.json config (see repos.json below for what this file does).

```
REPOS_JSON_PATH=/path/to/repos.json
```

### repos.json

This is how you tell the webhook listener what to do when data is received.

```
{
    "razius/puppet": {
        "path": "/home/puppet",
        "key": "MyVerySecretKey",
        "action": [["git", "pull", "origin", "master"]]
    },
    "d3non/somerandomexample/branch:live": {
        "path": "/home/exampleapp",
        "key": "MyVerySecretKey",
        "action": [
          ["git", "pull", "origin", "live"],
          ["echo", "execute", "some", "commands", "..."]
        ]
    }
}
```
