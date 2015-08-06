#!/usr/bin/env python

###
# Based on https://github.com/razius/github-webhook-handler/blob/master/index.py
###

import os
import re
import io
import json
import subprocess
import ipaddress
import requests
import hmac
from hashlib import sha1
from flask import Flask, request, abort
app = Flask(__name__)


@app.route("/", methods=['GET', 'POST'])
def hello():
  if request.method == 'GET':
    return 'OK'
  elif request.method == 'POST':
    # Store the IP address of the requester
    request_ip = ipaddress.ip_address(u'{0}'.format(request.remote_addr))

    # Get the hook address blocks from the github API.
    hook_blocks = requests.get('https://api.github.com/meta').json()[
        'hooks']

    # Check if the POST request is from github.com or GHE
    for block in hook_blocks:
      if ipaddress.ip_address(request_ip) in ipaddress.ip_network(block):
        break  # the remote_addr is within the network range of github.
    else:
      abort(403)

    if request.headers.get('X-GitHub-Event') == "ping":
      return json.dumps({'msg': 'Hi!'})
    if request.headers.get('X-GitHub-Event') != "push":
      return json.dumps({'msg': "wrong event type"})

    repos = json.loads(io.open(REPOS_JSON_PATH, 'r').read())

    payload = json.loads(request.data)
    repo_meta = {
        'name': payload['repository']['name'],
        'owner': payload['repository']['owner']['name'],
    }

    # Try to match on branch as configured in repos.json
    match = re.match(r"refs/heads/(?P<branch>.*)", payload['ref'])
    if match:
      repo_meta['branch'] = match.groupdict()['branch']
      repo = repos.get(
          '{owner}/{name}/branch:{branch}'.format(**repo_meta), None)

      # Fallback to plain owner/name lookup
      if not repo:
        repo = repos.get('{owner}/{name}'.format(**repo_meta), None)

    if repo and repo.get('path', None):
      # Check if POST request signature is valid
      key = repo.get('key', None)
      if key:
        signature = request.headers.get('X-Hub-Signature').split(
            '=')[1]
        if type(key) == unicode:
          key = key.encode()
        mac = hmac.new(key, msg=request.data, digestmod=sha1)
        if not compare_digest(mac.hexdigest(), signature):
          abort(403)

      if repo.get('action', None):
        for action in repo['action']:
          subp = subprocess.Popen(action, cwd=repo['path'])
          subp.wait()
    return 'OK'


if __name__ == "__main__":
  app.run()
