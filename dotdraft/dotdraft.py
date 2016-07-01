#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" .draft -- a carrot for open science """

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

__all__ = ["webhook"]

import json
import logging
import os
import requests
import signal
import subprocess
import yaml
from collections import deque
from random import choice
from re import search as re_search
from string import (ascii_uppercase, digits)
from tempfile import mkdtemp

# This is so dumb.
import github 
import pygithub3 as pygithub

GH_TOKEN = os.environ["GH_TOKEN"]
HEROKU_URL = os.environ["HEROKU_URL"] # There must be a better way..

# General utilities.
class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm

def random_string(N=10):
    """ Return a random string of alphanumeric characters of length `N`. """
    return ''.join(choice(ascii_uppercase + digits) for _ in range(N))


# Specific methods.
def git(command, cwd=None, shell=True, **kwargs):
    """
    Execute a git command (e.g., git `command`).

    :param command:
        The git command to execute.

    :param cwd: [optional]
        The current working directory where to execute the git command.

    :param shell: [optional]
        Whether to execute the command in a shell.

    :returns:
        The output from the git command.
    """
    
    try:
        result = subprocess.check_output("git {}".format(command), 
            cwd=cwd, shell=shell, **kwargs)

    except subprocess.CalledProcessError:
        raise

    else:
        return result


def is_valid_github_request(request):
    """
    Check whether a HTTP request is a valid ping from GitHub.

    :param request:
        The Django WSGI request.
    """

    # Check the metadata headers.
    required_meta_headers = {
        "HTTP_X_GITHUB_EVENT": ("pull_request", "push"),
        "HTTP_X_GITHUB_DELIVERY": None
    }
    for key, acceptable_values in required_meta_headers.items():
        
        # Only a key required?
        if key not in request.environ:
            return False

        # Specific values are acceptable.
        if  acceptable_values is not None \
        and request.environ[key] not in acceptable_values:
            return False


    # Check the payload.
    logging.info("Valid GitHub push request detected.")
    return True


def get_commit_comparisons(payload, repository_path=None):
    """
    Get the hashs of two commits that will be compared. A previous commit hash
    can be specified in the commit message, or will default to the previous
    commit on the same branch.

    :param payload:
        An event payload sent by GitHub.
        See https://developer.github.com/v3/activity/events/types/ for details.

    :param repository_path: [optional]
        A local folder containing the head of the repository that triggered the
        GitHub `payload`. This is necessary to check if a specific hash is valid
        (e.g., one that was specified by a commit message).

    :returns:
        A two-length tuple of the commit hashes to compare against (prev, now).
        If there is no previous commit, then the first item in the tuple will be
        `None`.
    """

    # We are on a commit.
    after_hash = payload["after"]
    prev_hash = payload["before"]   if len(payload["commits"]) == 1 \
                                    else payload["commits"][-2]["id"]

    # Check the commit message for something like [dd <hash>] or just [dd].
    m = re_search(
        "\[[d|D]{2}(\s[a-zA-Z0-9]+)*\]", payload["commits"][-1]["message"])

    if m is not None:
        if repository_path is None:
            raise ValueError(
                "a clone of the repository is necessary to check "
                "for valid commits")

        # Need to check that the hash is valid.
        hash_stub = m.group(0).rstrip("]").split(" ")
        if len(hash_stub) > 1:
            hash_stub = hash_stub[-1]

            try:
                r = git("cat-file -t {}".format(hash_stub), cwd=repository_path)
            
            except subprocess.CalledProcessError:
                # Invalid hash stub. Use the previous commit.
                logging.exception(
                    "Invalid hash stub given '{}':".format(hash_stub))
                
            else:
                prev_hash = hash_stub
    
    else:
        return (None, after_hash)

    # When this is the initial commit, GitHub gives a before hash of
    # '0000000000000000000000000000000000000000'
    if prev_hash == ("0"*40): prev_hash = None

    return (prev_hash, after_hash)


def get_manuscript_path(repository_path):
    """
    Get the path of the manuscript TeX file that will be used for comparisons.
    This defaults to the most edited `*.tex` file in the repository.

    :param repository_path:
        A local folder containing the head of the repository.

    :returns:
        The basename of the most edited `*.tex` file in the repository, 
        or `None` if no `*.tex` files could be found.
    """

    try:
        r = git('log --pretty=format: --name-only | sort | uniq -c |'\
                'sort -rg | grep ".tex$"', cwd=repository_path)
    
    except subprocess.CalledProcessError:
        logging.exception(
            "Cannot find any TeX files in repo at {}".format(repository_path))

        # TODO: Comment back on the repo? Send something? Anything?
        raise
        
    # Just in case the manuscript has spaces in it..
    basename = " ".join(str(r).split("\n")[0].strip().split()[1:])
    return basename


def load_settings(repository_path=None):
    """
    Load settings, optionally from a repository.

    :param repository_path: [optional]
        A local folder containing the head of the repository to look for a
        `.draft.yaml` file. If `None` is given, then the default options will
        be returned.

    :returns:
        A dictionary containing settings to use when performing the revision
        checks.
    """

    # Load defaults.
    with open(os.path.join(os.path.dirname(__file__), ".draft.yml"), "r") as fp:
        settings = yaml.load(fp)

    if repository_path is not None:
        path = os.path.join(repository_path, ".draft.yml")
        if os.path.exists(path):
            logging.info("Loading settings from {}".format(path))

            try:
                with open(path, "r") as fp:
                    given_settings = yaml.load(fp)

            except yaml.YAMLError:
                logging.exception("Cannot parse settings from {}".format(path))

            else:
                given_settings = given_settings or {}
                given_settings \
                    = dict((k.lower(), v) for k, v in given_settings.items())

                # Validate the settings so that we don't allow trickery.
                acceptable = {
                    "latex": ("pdflatex", ),
                }
                for key in set(given_settings).intersection(acceptable):
                    if given_settings[key] in acceptable[key]:
                        settings[key] = given_settings[key]

    return settings


def clone_repository(payload, branch=None):
    """
    Clone the repository that triggered the given event payload.

    :param payload:
        An event payload sent by GitHub. 
        See https://developer.github.com/v3/activity/events/types/ for details.

    :param branch: [optional]
        Specify the branch to clone.

    :returns:
        A temporary working directory where the repository has been cloned to.
    """

    twd = mkdtemp()
    branch = "" if branch is None else "-b {}".format(branch)

    r = git("clone {} {} {}".format(
        branch, payload["repository"]["clone_url"], twd))
    
    return twd


def latexdiff(old_path, new_path, **kwargs):
    """
    Run LaTeX-diff between an old manuscript and a new manuscript, and save the
    difference to a random (unused) filename in the path.

    :param old_path:
        The complete path of the old (before) manuscript.

    :param new_path:
        The complete path of the new (after) manuscript.

    :returns:
        The complete path of a new file that contains the LaTeX difference of
        the old and new files.
    """

    # Generate a temporary unused path for the difference file.
    repository_path = os.path.dirname(old_path)

    diff_path = get_unused_filename(repository_path, suffix=".diff.tex")

    # Execute latexdiff given some acceptable keywords.
    # TODO: allow keywords to get passed through here.
    command = './app/latexdiff "{}" "{}" > "{}"'.format(old_path, new_path, diff_path)
    logging.debug("latexdiff command: {}".format(command))

    try:
        r = subprocess.check_output(command, shell=True)

    except subprocess.CalledProcessError:
        logging.exception("Exception when calling: {}".format(command))
        raise

    else:
        print("diff path", diff_path)
        os.system("cat {}".format(diff_path))
        print("k done moarhax pls")
        return diff_path



def latex(path, timeout=30, **kwargs):
    """
    Compile the TeX document in the specified path.

    :param path:
        The location of a TeX file to compile.

    :returns:
        A three-length tuple containing the full path of the compiled PDF, the
        stdout, and the stderr.
    """

    p = subprocess.Popen([kwargs["latex"]], #cwd=os.path.dirname(path),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        shell=True)

    if timeout != -1:
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(timeout)

    try:

        stdout, stderr = p.communicate("{}\n".format(path))
        logging.info("latex stdout:\n{}".format(stdout))
        logging.info("latex stderr:\n{}".format(stderr))

        if timeout != -1:
            signal.alarm(0)

    except Alarm:

        # process might have died before getting to this line
        # so wrap to avoid OSError: no such process
        try:
            os.kill(p.pid, signal.SIGKILL)

        except OSError:
            pass
        
        raise OSError("timeout")

    base_path, ext = os.path.splitext(path)
    compiled_pdf = os.path.basename(os.path.extsep.join([base_path, "pdf"]))

    return (compiled_pdf, stdout, stderr)


def get_unused_filename(folder, suffix=None, N=10):
    """
    Get a temporary filename.

    :param folder:
        The folder.

    :param suffix: [optional]
        An optional suffix to add to the filename.

    :param N: [optional]
        Length of the basename (ignoring the suffix).

    :returns:
        The full path name.
    """

    suffix = suffix or ""

    basename = "".join([random_string(N=N), suffix])
    while os.path.exists(os.path.join(folder, basename)):
        basename = "".join([random_string(N=N), suffix])

    return os.path.join(folder, basename)


def copy_previous_manuscript(repository_path, before_hash, manuscript_basename):
    """
    Retrieve a copy of the manuscript filename from a repository at a particular
    commit. The previous manuscript will be copied to a unique temporary path in
    the top-level of the repository.

    :param repository_path:
        A local folder containing a repository.

    :param before_hash:
        The hash (or hash stub) of a commit to checkout before retrieving the
        `manuscript_basename`.

    :param manuscript_basename:
        The path of the manuscript file relative to the top-level repository
        path.

    :returns:
        A temporary (complete) path of a TeX file that contains the manuscript
        at the time of the `before_hash` commit.
    """

    # Generate a temporary filename.    
    before_basename = "{}.tex".format(random_string())
    while os.path.exists(os.path.join(repository_path, before_basename)):
        before_basename = "{}.tex".format(random_string())

    # TODO FAIL
    r = git("show {}:{} > {}".format(
            before_hash, os.path.basename(manuscript_basename), before_basename),
        cwd=repository_path)

    return os.path.join(repository_path, before_basename)


def webhook(request, database=None, status_context=".draft/revisions"):
    """
    Method to run when GitHub has triggered an event on a repository.

    :param request:
        A WSGI request, which might have come from GitHub.

    :param database: [optional]
        A Postgres database to store compiled PDFs in. If `None` is supplied,
        then files will be uploaded to a temporary site.
    """

    logging.info("Received webhook: {}".format(request))

    # Check the request is from GitHub, otherwise do nothing.
    if not is_valid_github_request(request):
        logging.info("Not valid GitHub request. Ignoring.")
        return False

    payload = json.loads(request.get_data())

    on_pull_request = (request.environ["HTTP_X_GITHUB_EVENT"] == "pull_request")
    if on_pull_request and payload["pull_request"]["state"] != "open":
        logging.info("Webhook triggered by closed pull request. Ignoring.")
        return None

    elif on_pull_request:
        logging.info("Webhook triggered by open pull request.")

        logging.info("Comparing refs {} with {}".format(
            payload["pull_request"]["base"]["ref"],
            payload["pull_request"]["head"]["ref"]))
        
        # Clone the base and head repositories.
        base_repository = clone_repository(
            payload, payload["pull_request"]["base"]["ref"])

        head_repository = clone_repository(
            payload, payload["pull_request"]["head"]["ref"])

        # Get the manuscript paths.
        settings = load_settings(base_repository)

        # What is the name of the manuscript?
        manuscript_basename =  settings.get("manuscript", None) \
                            or get_manuscript_path(base_repository)

        # Get the paths.
        base_path = os.path.join(base_repository, manuscript_basename)
        head_path = os.path.join(head_repository, manuscript_basename)

        logging.debug("Comparing paths {} with {}".format(base_path, head_path))

        # Keep the SHAs.
        head_sha = payload["pull_request"]["head"]["sha"]
        base_sha = payload["pull_request"]["base"]["sha"]

        logging.debug("Comparing SHAs {} with {}".format(base_sha, head_sha))

        repo = payload["repository"]["name"]
        owner = payload["repository"]["owner"]["login"]
        uri = "{owner}.{repo}.{issue}.pdf".format(
            owner=owner, repo=repo, issue=payload["number"])

        # Update status.
        gh = github.Github(login_or_token=GH_TOKEN)
        pr = gh.get_repo("{}/{}".format(owner, repo)).get_pull(payload["number"])
        commit = deque(pr.get_commits(), maxlen=1).pop()

        description = ".draft is compiling your differenced PDF"
        commit.create_status("pending", target_url=HEROKU_URL,
            description=description, context=status_context)

        logging.info("Updated status context on {}/{}/{}: {} - {}".format(
            owner, repo, payload["number"], status_context, description))


    else:
        logging.info("Webhook triggered by commit(s)")

        # Clone the repository.
        repository_path = clone_repository(payload)

        # Get the manuscript paths.
        settings = load_settings(repository_path)

        # What is the name of the manuscript?
        manuscript_basename =  settings.get("manuscript", None) \
                            or get_manuscript_path(repository_path)

        # Check the commit message for a previous SHA.
        base_sha, head_sha = get_commit_comparisons(payload, repository_path)

        if base_sha is None:
            logging.info("No base SHA found; nothing to do.")
            return None

        # base = original; head = changed
        head_path = os.path.join(repository_path, manuscript_basename)
        base_path = copy_previous_manuscript(
            repository_path, base_sha, manuscript_basename)
    
        owner = payload["repository"]["owner"]["name"]
        uri = "{owner}.{repo}.{base}..{head}.pdf".format(owner=owner,
            repo=payload["repository"]["name"],
            base=base_sha[:6], head=head_sha[:6])


    # Run difftex on the before and after.
    manuscript_diff = latexdiff(base_path, head_path, **settings)

    logging.debug("Result of latexdiff: {}".format(manuscript_diff))

    # Compile the manuscript_diff file.
    compiled_diff, stdout, stderr = latex(manuscript_diff, **settings)

    # Check things were OK.
    success = os.path.exists(compiled_diff)
    if success:
        logging.info("Created diff PDF successfully: {}".format(compiled_diff))

        # The compiled PDF either needs to be stored in a Postgres database as a
        # blob, or uploaded and linked elsewhere.

        if database is None:
            logging.warn("No database supplied. Using transfer.sh instead..")

            upload_response = requests.put(
                url="https://transfer.sh/{}".format(uri),
                data=open(compiled_diff, "rb"))

            if upload_response.status_code == 200:
                target_url = response.text.strip()
                logging.info("Compiled PDF uploaded successfully to {}".format(
                    target_url))

            else:
                target_url = HEROKU_URL # TODO
                logging.warn("Upload failed: {}".format(
                    upload_response.status_code))


        else:
            raise NotImplementedError("db not set up yet")


    else:
        target_url = HEROKU_URL # TODO
        message =   "Something went wrong when trying to compile the PDF "\
                    "between `{}` and `{}`:\n\n"\
                    "````\n"\
                    "{}"\
                    "````\n".format(base_sha[:10], head_sha[:10], stdout)

    gh = pygithub.Github(token=GH_TOKEN)

    if on_pull_request and success:
        commit.create_status("success", 
            target_url=target_url,
            description=".draft compiled the differences "\
                        "between {} and {}".format(
                            base_sha[:4], head_sha[:4]),
            context=status_context)

        if database is None:
            r = gh.issues.comments.create(payload["number"],
                "*Warning:* The link to the compiled PDF is not persistent and "
                "will expire in two weeks. Set up `.draft` with a free Postgres"
                " database to enable persistent links",
                user=owner, repo=payload["repository"]["name"])

    elif on_pull_request and not success:

        commit.create_status("failure", 
            description=".draft build failure. See log for details.",
            target_url=target_url, context=status_context)

        r = gh.issues.comments.create(payload["number"], message, 
            user=owner, repo=payload["repository"]["name"])

    else:

        # Comment on the commit.
        comment_payload = {
            "commit_id": head_sha,
            "path": os.path.basename(head_path),
            "position": 1,
            "line": 1,
            "body": message
        }
        result = gh.repos.commits.create_comment(comment_payload, sha=head_sha,
            user=owner, repo=payload["repository"]["name"])

    return True


