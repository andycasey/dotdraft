#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" .draft -- a carrot for open science """

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

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

logger = logging.getLogger(__name__)

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
        if key not in request.META:
            return False

        # Specific values are acceptable.
        if  acceptable_values is not None \
        and request.META[key] not in acceptable_values:
            return False


    # Check the payload.
    logger.info("Valid GitHub push request detected.")
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
                logger.exception(
                    "Invalid hash stub given '{}':".format(hash_stub))
                
            else:
                prev_hash = hash_stub
    
    else:
        return (None, after_hash)

    # When this is the initial commit, GitHub gives a before hash of
    # '0000000000000000000000000000000000000000'
    if prev_hash == ("0"*40): prev_hash = None

    return (prev_hash, after_hash)


# TODO: This can probably go into a GHPayload class.
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
        logger.exception(
            "Cannot find any TeX files in repo at {}".format(repository_path))
        return None

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
            logger.info("Loading settings from {}".format(path))

            try:
                with open(path, "r") as fp:
                    given_settings = yaml.load(fp)

            except yaml.YAMLError:
                logger.exception("Cannot parse settings from {}".format(path))

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
    command = './hello/latexdiff "{}" "{}" > "{}"'.format(old_path, new_path, diff_path)
    try:
        r = subprocess.check_output(command, shell=True)

    except subprocess.CalledProcessError:
        logger.exception("Exception when calling: {}".format(command))
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
        print("stdout", stdout)
        print("stderr", stderr)

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


def trigger_event(request):
    """
    Method to run when GitHub has triggered an event on a repository.

    :param request:
        A WSGI request, which might have come from GitHub.
    """

    # Check the request is from GitHub, otherwise do nothing.
    if not is_valid_github_request(request):
        return False


    status_context = ".draft/revisions"
    on_pull_request = (request.META["HTTP_X_GITHUB_EVENT"] == "pull_request")

    payload = request.body
    if not isinstance(payload, dict): payload = json.loads(payload)


    if on_pull_request and payload["pull_request"]["state"] != "open":
        return None

    elif on_pull_request:
        print("PR payload", payload)

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

        # Keep the SHAs.
        head_sha = payload["pull_request"]["head"]["sha"]
        base_sha = payload["pull_request"]["base"]["sha"]

        repo = payload["repository"]["name"]
        owner = payload["repository"]["owner"]["login"]
        uri = "{owner}.{repo}.{issue}.pdf".format(
            owner=owner, repo=repo, issue=payload["number"])

        # Update status.
        gh = github.Github(login_or_token=GH_TOKEN)
        pr = gh.get_repo("{}/{}".format(owner, repo)).get_pull(payload["number"])
        commit = deque(pr.get_commits(), maxlen=1).pop()

        commit.create_status("pending", target_url=HEROKU_URL,
            description=".draft is compiling your differenced PDF",
            context=status_context)


    else:
        print("CM payload", payload)

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
            logger.info("No base SHA found; nothing to do.")
            return None

        # head = changed.
        head_path = os.path.join(repository_path, manuscript_basename)
        base_path = copy_previous_manuscript(
            repository_path, base_sha, manuscript_basename)
    
        owner = payload["repository"]["owner"]["name"]
        uri = "{owner}.{repo}.{base}..{head}.pdf".format(owner=owner,
            repo=payload["repository"]["name"],
            base=base_sha[:6], head=head_sha[:6])


    # Run difftex on the before and after.
    manuscript_diff = latexdiff(base_path, head_path, **settings)

    # Compile the manuscript_diff file.
    compiled_diff, stdout, stderr = latex(manuscript_diff, **settings)

    # Check things were OK.
    success = os.path.exists(compiled_diff)
    if success:

        # Re-name the compiled_diff
        os.system("mv {} app/static/{}".format(compiled_diff, uri))

        # TODO: Heroku deletes it when the dyno spins down. Do I need to commit
        #       it to the Heroku repository?

    else:
        message =   "Something went wrong when trying to compile the PDF "\
                    "between `{}` and `{}`:\n\n"\
                    "````\n"\
                    "{}"\
                    "````\n".format(base_sha[:10], head_sha[:10], stdout)

    gh = pygithub.Github(token=GH_TOKEN)

    if on_pull_request and success:
        commit.create_status("success", 
            target_url="{}/static/{}".format(HEROKU_URL, uri),
            description=".draft compiled the difference "\
                        "between {} and {}".format(
                            base_sha[:4], head_sha[:4]),
            context=status_context)


    elif on_pull_request and not success:

        commit.create_status("failure", 
            description=".draft build failure. See log for details.",
            target_url=HEROKU_URL, context=status_context)

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

    return None




if __name__ == "__main__":

    # Trigger a fake request.
    class Request:
        pass

    gh_push = Request()
    # Headers.
    gh_push.META = {
        "HTTP_X_GITHUB_EVENT": "pull_request",
        "HTTP_X_GITHUB_DELIVERY": "foo"
    }
    # Payload.
    import json
    gh_push.body = json.loads("""{"ref":"refs/heads/master","before":"02347269144be23ee7249a2e6908d5cf3bad118d","after":"39e57119c2799a492bd1e073bdd228d9114e9de1","created":false,"deleted":false,"forced":false,"base_ref":null,"compare":"https://github.com/andycasey/heroku-webhook-ping/compare/02347269144b...39e57119c279","commits":[{"id":"787a6ce24fc2dee18d081ebc4e97085662e1f4a9","tree_id":"0e6e381203b93eea77f6c809c054a74ad9b4c4ff","distinct":true,"message":"Add a thing","timestamp":"2016-06-22T14:10:35+01:00","url":"https://github.com/andycasey/heroku-webhook-ping/commit/787a6ce24fc2dee18d081ebc4e97085662e1f4a9","author":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"committer":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"added":["ms.tex"],"removed":[],"modified":[]},{"id":"39e57119c2799a492bd1e073bdd228d9114e9de1","tree_id":"af1035059a34a5989d8dfb2e6c730ced637f4388","distinct":true,"message":"foo [dd]","timestamp":"2016-06-22T14:14:10+01:00","url":"https://github.com/andycasey/heroku-webhook-ping/commit/39e57119c2799a492bd1e073bdd228d9114e9de1","author":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"committer":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"added":[],"removed":[],"modified":["ms.tex"]}],"head_commit":{"id":"39e57119c2799a492bd1e073bdd228d9114e9de1","tree_id":"af1035059a34a5989d8dfb2e6c730ced637f4388","distinct":true,"message":"foo [dd]","timestamp":"2016-06-22T14:14:10+01:00","url":"https://github.com/andycasey/heroku-webhook-ping/commit/39e57119c2799a492bd1e073bdd228d9114e9de1","author":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"committer":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"added":[],"removed":[],"modified":["ms.tex"]},"repository":{"id":61547239,"name":"heroku-webhook-ping","full_name":"andycasey/heroku-webhook-ping","owner":{"name":"andycasey","email":"andycasey@gmail.com"},"private":false,"html_url":"https://github.com/andycasey/heroku-webhook-ping","description":"","fork":false,"url":"https://github.com/andycasey/heroku-webhook-ping","forks_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/forks","keys_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/keys{/key_id}","collaborators_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/collaborators{/collaborator}","teams_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/teams","hooks_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/hooks","issue_events_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/events{/number}","events_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/events","assignees_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/assignees{/user}","branches_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/branches{/branch}","tags_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/tags","blobs_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/blobs{/sha}","git_tags_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/tags{/sha}","git_refs_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/refs{/sha}","trees_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/trees{/sha}","statuses_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/statuses/{sha}","languages_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/languages","stargazers_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/stargazers","contributors_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/contributors","subscribers_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/subscribers","subscription_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/subscription","commits_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/commits{/sha}","git_commits_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/commits{/sha}","comments_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/comments{/number}","issue_comment_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/comments{/number}","contents_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/contents/{+path}","compare_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/compare/{base}...{head}","merges_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/merges","archive_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/{archive_format}{/ref}","downloads_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/downloads","issues_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/issues{/number}","pulls_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls{/number}","milestones_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/milestones{/number}","notifications_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/notifications{?since,all,participating}","labels_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/labels{/name}","releases_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/releases{/id}","deployments_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/deployments","created_at":1466426913,"updated_at":"2016-06-20T12:48:33Z","pushed_at":1466601254,"git_url":"git://github.com/andycasey/heroku-webhook-ping.git","ssh_url":"git@github.com:andycasey/heroku-webhook-ping.git","clone_url":"https://github.com/andycasey/heroku-webhook-ping.git","svn_url":"https://github.com/andycasey/heroku-webhook-ping","homepage":null,"size":1,"stargazers_count":0,"watchers_count":0,"language":null,"has_issues":true,"has_downloads":true,"has_wiki":true,"has_pages":false,"forks_count":0,"mirror_url":null,"open_issues_count":0,"forks":0,"open_issues":0,"watchers":0,"default_branch":"master","stargazers":0,"master_branch":"master"},"pusher":{"name":"andycasey","email":"andycasey@gmail.com"},"sender":{"login":"andycasey","id":504436,"avatar_url":"https://avatars.githubusercontent.com/u/504436?v=3","gravatar_id":"","url":"https://api.github.com/users/andycasey","html_url":"https://github.com/andycasey","followers_url":"https://api.github.com/users/andycasey/followers","following_url":"https://api.github.com/users/andycasey/following{/other_user}","gists_url":"https://api.github.com/users/andycasey/gists{/gist_id}","starred_url":"https://api.github.com/users/andycasey/starred{/owner}{/repo}","subscriptions_url":"https://api.github.com/users/andycasey/subscriptions","organizations_url":"https://api.github.com/users/andycasey/orgs","repos_url":"https://api.github.com/users/andycasey/repos","events_url":"https://api.github.com/users/andycasey/events{/privacy}","received_events_url":"https://api.github.com/users/andycasey/received_events","type":"User","site_admin":false}}""")

    # do something:
    gh_push.body = json.loads("""{"ref":"refs/heads/master","before":"b96cee3d2d9f10c7cac3dc80ed3e1cfdcc8db4dd","after":"a800ba57ff28b15d109216bccdf9e169c867d0f5","created":false,"deleted":false,"forced":false,"base_ref":null,"compare":"https://github.com/andycasey/heroku-webhook-ping/compare/b96cee3d2d9f...a800ba57ff28","commits":[{"id":"a800ba57ff28b15d109216bccdf9e169c867d0f5","tree_id":"ca5caf124afbd807a7f91f1d1229c9100ba7a4f3","distinct":true,"message":"changes [dd]","timestamp":"2016-06-22T16:29:17+01:00","url":"https://github.com/andycasey/heroku-webhook-ping/commit/a800ba57ff28b15d109216bccdf9e169c867d0f5","author":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"committer":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"added":[],"removed":[],"modified":["ms.tex"]}],"head_commit":{"id":"a800ba57ff28b15d109216bccdf9e169c867d0f5","tree_id":"ca5caf124afbd807a7f91f1d1229c9100ba7a4f3","distinct":true,"message":"changes [dd]","timestamp":"2016-06-22T16:29:17+01:00","url":"https://github.com/andycasey/heroku-webhook-ping/commit/a800ba57ff28b15d109216bccdf9e169c867d0f5","author":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"committer":{"name":"Andy Casey","email":"andycasey@gmail.com","username":"andycasey"},"added":[],"removed":[],"modified":["ms.tex"]},"repository":{"id":61547239,"name":"heroku-webhook-ping","full_name":"andycasey/heroku-webhook-ping","owner":{"name":"andycasey","email":"andycasey@gmail.com"},"private":false,"html_url":"https://github.com/andycasey/heroku-webhook-ping","description":"","fork":false,"url":"https://github.com/andycasey/heroku-webhook-ping","forks_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/forks","keys_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/keys{/key_id}","collaborators_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/collaborators{/collaborator}","teams_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/teams","hooks_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/hooks","issue_events_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/events{/number}","events_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/events","assignees_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/assignees{/user}","branches_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/branches{/branch}","tags_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/tags","blobs_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/blobs{/sha}","git_tags_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/tags{/sha}","git_refs_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/refs{/sha}","trees_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/trees{/sha}","statuses_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/statuses/{sha}","languages_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/languages","stargazers_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/stargazers","contributors_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/contributors","subscribers_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/subscribers","subscription_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/subscription","commits_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/commits{/sha}","git_commits_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/git/commits{/sha}","comments_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/comments{/number}","issue_comment_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/comments{/number}","contents_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/contents/{+path}","compare_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/compare/{base}...{head}","merges_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/merges","archive_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/{archive_format}{/ref}","downloads_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/downloads","issues_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/issues{/number}","pulls_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls{/number}","milestones_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/milestones{/number}","notifications_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/notifications{?since,all,participating}","labels_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/labels{/name}","releases_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/releases{/id}","deployments_url":"https://api.github.com/repos/andycasey/heroku-webhook-ping/deployments","created_at":1466426913,"updated_at":"2016-06-22T13:14:15Z","pushed_at":1466609364,"git_url":"git://github.com/andycasey/heroku-webhook-ping.git","ssh_url":"git@github.com:andycasey/heroku-webhook-ping.git","clone_url":"https://github.com/andycasey/heroku-webhook-ping.git","svn_url":"https://github.com/andycasey/heroku-webhook-ping","homepage":null,"size":2,"stargazers_count":0,"watchers_count":0,"language":"TeX","has_issues":true,"has_downloads":true,"has_wiki":true,"has_pages":false,"forks_count":0,"mirror_url":null,"open_issues_count":0,"forks":0,"open_issues":0,"watchers":0,"default_branch":"master","stargazers":0,"master_branch":"master"},"pusher":{"name":"andycasey","email":"andycasey@gmail.com"},"sender":{"login":"andycasey","id":504436,"avatar_url":"https://avatars.githubusercontent.com/u/504436?v=3","gravatar_id":"","url":"https://api.github.com/users/andycasey","html_url":"https://github.com/andycasey","followers_url":"https://api.github.com/users/andycasey/followers","following_url":"https://api.github.com/users/andycasey/following{/other_user}","gists_url":"https://api.github.com/users/andycasey/gists{/gist_id}","starred_url":"https://api.github.com/users/andycasey/starred{/owner}{/repo}","subscriptions_url":"https://api.github.com/users/andycasey/subscriptions","organizations_url":"https://api.github.com/users/andycasey/orgs","repos_url":"https://api.github.com/users/andycasey/repos","events_url":"https://api.github.com/users/andycasey/events{/privacy}","received_events_url":"https://api.github.com/users/andycasey/received_events","type":"User","site_admin":false}}""")

    # PR:
    gh_push.body = {u'repository': {u'fork': False, u'created_at': u'2016-06-20T12:48:33Z', u'private': False, u'teams_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/teams', u'hooks_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/hooks', u'downloads_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/downloads', u'git_refs_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/refs{/sha}', u'stargazers_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/stargazers', u'labels_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/labels{/name}', u'homepage': None, u'issue_events_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/events{/number}', u'stargazers_count': 0, u'notifications_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/notifications{?since,all,participating}', u'svn_url': u'https://github.com/andycasey/heroku-webhook-ping', u'merges_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/merges', u'blobs_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/blobs{/sha}', u'url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping', u'comments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/comments{/number}', u'keys_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/keys{/key_id}', u'has_downloads': True, u'name': u'heroku-webhook-ping', u'owner': {u'organizations_url': u'https://api.github.com/users/andycasey/orgs', u'gists_url': u'https://api.github.com/users/andycasey/gists{/gist_id}', u'received_events_url': u'https://api.github.com/users/andycasey/received_events', u'html_url': u'https://github.com/andycasey', u'repos_url': u'https://api.github.com/users/andycasey/repos', u'gravatar_id': u'', u'starred_url': u'https://api.github.com/users/andycasey/starred{/owner}{/repo}', u'login': u'andycasey', u'avatar_url': u'https://avatars.githubusercontent.com/u/504436?v=3', u'id': 504436, u'followers_url': u'https://api.github.com/users/andycasey/followers', u'site_admin': False, u'events_url': u'https://api.github.com/users/andycasey/events{/privacy}', u'following_url': u'https://api.github.com/users/andycasey/following{/other_user}', u'subscriptions_url': u'https://api.github.com/users/andycasey/subscriptions', u'url': u'https://api.github.com/users/andycasey', u'type': u'User'}, u'open_issues': 1, u'releases_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/releases{/id}', u'mirror_url': None, u'assignees_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/assignees{/user}', u'commits_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/commits{/sha}', u'clone_url': u'https://github.com/andycasey/heroku-webhook-ping.git', u'tags_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/tags', u'compare_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/compare/{base}...{head}', u'deployments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/deployments', u'full_name': u'andycasey/heroku-webhook-ping', u'ssh_url': u'git@github.com:andycasey/heroku-webhook-ping.git', u'collaborators_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/collaborators{/collaborator}', u'html_url': u'https://github.com/andycasey/heroku-webhook-ping', u'issue_comment_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/comments{/number}', u'archive_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/{archive_format}{/ref}', u'size': 4, u'git_commits_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/commits{/sha}', u'has_wiki': True, u'branches_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/branches{/branch}', u'pushed_at': u'2016-06-22T17:37:11Z', u'has_issues': True, u'contents_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/contents/{+path}', u'events_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/events', u'contributors_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/contributors', u'updated_at': u'2016-06-22T13:14:15Z', u'trees_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/trees{/sha}', u'languages_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/languages', u'has_pages': False, u'git_url': u'git://github.com/andycasey/heroku-webhook-ping.git', u'id': 61547239, u'watchers_count': 0, u'milestones_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/milestones{/number}', u'git_tags_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/tags{/sha}', u'forks': 0, u'subscribers_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/subscribers', u'language': u'TeX', u'open_issues_count': 1, u'forks_count': 0, u'description': u'', u'issues_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues{/number}', u'watchers': 0, u'forks_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/forks', u'statuses_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/statuses/{sha}', u'subscription_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/subscription', u'default_branch': u'master', u'pulls_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls{/number}'}, u'number': 2, u'pull_request': {u'comments': 4, u'assignee': None, u'created_at': u'2016-06-22T17:37:11Z', u'commits': 1, u'body': u'', u'review_comments': 0, u'updated_at': u'2016-06-22T17:55:15Z', u'title': u'foobar [dd]', u'closed_at': None, u'base': {u'ref': u'master', u'sha': u'a800ba57ff28b15d109216bccdf9e169c867d0f5', u'user': {u'organizations_url': u'https://api.github.com/users/andycasey/orgs', u'gists_url': u'https://api.github.com/users/andycasey/gists{/gist_id}', u'received_events_url': u'https://api.github.com/users/andycasey/received_events', u'html_url': u'https://github.com/andycasey', u'repos_url': u'https://api.github.com/users/andycasey/repos', u'gravatar_id': u'', u'starred_url': u'https://api.github.com/users/andycasey/starred{/owner}{/repo}', u'login': u'andycasey', u'avatar_url': u'https://avatars.githubusercontent.com/u/504436?v=3', u'id': 504436, u'followers_url': u'https://api.github.com/users/andycasey/followers', u'site_admin': False, u'events_url': u'https://api.github.com/users/andycasey/events{/privacy}', u'following_url': u'https://api.github.com/users/andycasey/following{/other_user}', u'subscriptions_url': u'https://api.github.com/users/andycasey/subscriptions', u'url': u'https://api.github.com/users/andycasey', u'type': u'User'}, u'repo': {u'fork': False, u'created_at': u'2016-06-20T12:48:33Z', u'private': False, u'teams_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/teams', u'hooks_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/hooks', u'downloads_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/downloads', u'git_refs_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/refs{/sha}', u'stargazers_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/stargazers', u'labels_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/labels{/name}', u'homepage': None, u'issue_events_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/events{/number}', u'stargazers_count': 0, u'notifications_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/notifications{?since,all,participating}', u'svn_url': u'https://github.com/andycasey/heroku-webhook-ping', u'merges_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/merges', u'blobs_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/blobs{/sha}', u'url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping', u'comments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/comments{/number}', u'keys_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/keys{/key_id}', u'has_downloads': True, u'name': u'heroku-webhook-ping', u'owner': {u'organizations_url': u'https://api.github.com/users/andycasey/orgs', u'gists_url': u'https://api.github.com/users/andycasey/gists{/gist_id}', u'received_events_url': u'https://api.github.com/users/andycasey/received_events', u'html_url': u'https://github.com/andycasey', u'repos_url': u'https://api.github.com/users/andycasey/repos', u'gravatar_id': u'', u'starred_url': u'https://api.github.com/users/andycasey/starred{/owner}{/repo}', u'login': u'andycasey', u'avatar_url': u'https://avatars.githubusercontent.com/u/504436?v=3', u'id': 504436, u'followers_url': u'https://api.github.com/users/andycasey/followers', u'site_admin': False, u'events_url': u'https://api.github.com/users/andycasey/events{/privacy}', u'following_url': u'https://api.github.com/users/andycasey/following{/other_user}', u'subscriptions_url': u'https://api.github.com/users/andycasey/subscriptions', u'url': u'https://api.github.com/users/andycasey', u'type': u'User'}, u'open_issues': 1, u'releases_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/releases{/id}', u'mirror_url': None, u'assignees_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/assignees{/user}', u'commits_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/commits{/sha}', u'clone_url': u'https://github.com/andycasey/heroku-webhook-ping.git', u'tags_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/tags', u'compare_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/compare/{base}...{head}', u'deployments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/deployments', u'full_name': u'andycasey/heroku-webhook-ping', u'ssh_url': u'git@github.com:andycasey/heroku-webhook-ping.git', u'collaborators_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/collaborators{/collaborator}', u'html_url': u'https://github.com/andycasey/heroku-webhook-ping', u'issue_comment_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/comments{/number}', u'archive_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/{archive_format}{/ref}', u'size': 4, u'git_commits_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/commits{/sha}', u'has_wiki': True, u'branches_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/branches{/branch}', u'pushed_at': u'2016-06-22T17:37:11Z', u'has_issues': True, u'contents_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/contents/{+path}', u'events_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/events', u'contributors_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/contributors', u'updated_at': u'2016-06-22T13:14:15Z', u'trees_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/trees{/sha}', u'languages_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/languages', u'has_pages': False, u'git_url': u'git://github.com/andycasey/heroku-webhook-ping.git', u'id': 61547239, u'watchers_count': 0, u'milestones_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/milestones{/number}', u'git_tags_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/tags{/sha}', u'forks': 0, u'subscribers_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/subscribers', u'language': u'TeX', u'open_issues_count': 1, u'forks_count': 0, u'description': u'', u'issues_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues{/number}', u'watchers': 0, u'forks_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/forks', u'statuses_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/statuses/{sha}', u'subscription_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/subscription', u'default_branch': u'master', u'pulls_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls{/number}'}, u'label': u'andycasey:master'}, u'state': u'open', u'review_comment_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/comments{/number}', u'diff_url': u'https://github.com/andycasey/heroku-webhook-ping/pull/2.diff', u'patch_url': u'https://github.com/andycasey/heroku-webhook-ping/pull/2.patch', u'issue_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/2', u'url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/2', u'number': 2, u'mergeable': None, u'commits_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/2/commits', u'user': {u'organizations_url': u'https://api.github.com/users/andycasey/orgs', u'gists_url': u'https://api.github.com/users/andycasey/gists{/gist_id}', u'received_events_url': u'https://api.github.com/users/andycasey/received_events', u'html_url': u'https://github.com/andycasey', u'repos_url': u'https://api.github.com/users/andycasey/repos', u'gravatar_id': u'', u'starred_url': u'https://api.github.com/users/andycasey/starred{/owner}{/repo}', u'login': u'andycasey', u'avatar_url': u'https://avatars.githubusercontent.com/u/504436?v=3', u'id': 504436, u'followers_url': u'https://api.github.com/users/andycasey/followers', u'site_admin': False, u'events_url': u'https://api.github.com/users/andycasey/events{/privacy}', u'following_url': u'https://api.github.com/users/andycasey/following{/other_user}', u'subscriptions_url': u'https://api.github.com/users/andycasey/subscriptions', u'url': u'https://api.github.com/users/andycasey', u'type': u'User'}, u'_links': {u'comments': {u'href': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/2/comments'}, u'statuses': {u'href': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/statuses/61b8b4de2d9c0327d66fcd660f2f39bf8736520a'}, u'self': {u'href': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/2'}, u'commits': {u'href': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/2/commits'}, u'review_comment': {u'href': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/comments{/number}'}, u'issue': {u'href': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/2'}, u'html': {u'href': u'https://github.com/andycasey/heroku-webhook-ping/pull/2'}, u'review_comments': {u'href': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/2/comments'}}, u'review_comments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls/2/comments', u'merged_at': None, u'milestone': None, u'html_url': u'https://github.com/andycasey/heroku-webhook-ping/pull/2', u'mergeable_state': u'unknown', u'merged': False, u'changed_files': 1, u'comments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/2/comments', u'merge_commit_sha': u'63bf60bf3fb1d14ba9a39886981a2b6af700e3e6', u'locked': False, u'deletions': 2, u'id': 74825737, u'head': {u'ref': u'new', u'sha': u'61b8b4de2d9c0327d66fcd660f2f39bf8736520a', u'user': {u'organizations_url': u'https://api.github.com/users/andycasey/orgs', u'gists_url': u'https://api.github.com/users/andycasey/gists{/gist_id}', u'received_events_url': u'https://api.github.com/users/andycasey/received_events', u'html_url': u'https://github.com/andycasey', u'repos_url': u'https://api.github.com/users/andycasey/repos', u'gravatar_id': u'', u'starred_url': u'https://api.github.com/users/andycasey/starred{/owner}{/repo}', u'login': u'andycasey', u'avatar_url': u'https://avatars.githubusercontent.com/u/504436?v=3', u'id': 504436, u'followers_url': u'https://api.github.com/users/andycasey/followers', u'site_admin': False, u'events_url': u'https://api.github.com/users/andycasey/events{/privacy}', u'following_url': u'https://api.github.com/users/andycasey/following{/other_user}', u'subscriptions_url': u'https://api.github.com/users/andycasey/subscriptions', u'url': u'https://api.github.com/users/andycasey', u'type': u'User'}, u'repo': {u'fork': False, u'created_at': u'2016-06-20T12:48:33Z', u'private': False, u'teams_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/teams', u'hooks_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/hooks', u'downloads_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/downloads', u'git_refs_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/refs{/sha}', u'stargazers_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/stargazers', u'labels_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/labels{/name}', u'homepage': None, u'issue_events_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/events{/number}', u'stargazers_count': 0, u'notifications_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/notifications{?since,all,participating}', u'svn_url': u'https://github.com/andycasey/heroku-webhook-ping', u'merges_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/merges', u'blobs_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/blobs{/sha}', u'url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping', u'comments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/comments{/number}', u'keys_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/keys{/key_id}', u'has_downloads': True, u'name': u'heroku-webhook-ping', u'owner': {u'organizations_url': u'https://api.github.com/users/andycasey/orgs', u'gists_url': u'https://api.github.com/users/andycasey/gists{/gist_id}', u'received_events_url': u'https://api.github.com/users/andycasey/received_events', u'html_url': u'https://github.com/andycasey', u'repos_url': u'https://api.github.com/users/andycasey/repos', u'gravatar_id': u'', u'starred_url': u'https://api.github.com/users/andycasey/starred{/owner}{/repo}', u'login': u'andycasey', u'avatar_url': u'https://avatars.githubusercontent.com/u/504436?v=3', u'id': 504436, u'followers_url': u'https://api.github.com/users/andycasey/followers', u'site_admin': False, u'events_url': u'https://api.github.com/users/andycasey/events{/privacy}', u'following_url': u'https://api.github.com/users/andycasey/following{/other_user}', u'subscriptions_url': u'https://api.github.com/users/andycasey/subscriptions', u'url': u'https://api.github.com/users/andycasey', u'type': u'User'}, u'open_issues': 1, u'releases_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/releases{/id}', u'mirror_url': None, u'assignees_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/assignees{/user}', u'commits_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/commits{/sha}', u'clone_url': u'https://github.com/andycasey/heroku-webhook-ping.git', u'tags_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/tags', u'compare_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/compare/{base}...{head}', u'deployments_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/deployments', u'full_name': u'andycasey/heroku-webhook-ping', u'ssh_url': u'git@github.com:andycasey/heroku-webhook-ping.git', u'collaborators_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/collaborators{/collaborator}', u'html_url': u'https://github.com/andycasey/heroku-webhook-ping', u'issue_comment_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues/comments{/number}', u'archive_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/{archive_format}{/ref}', u'size': 4, u'git_commits_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/commits{/sha}', u'has_wiki': True, u'branches_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/branches{/branch}', u'pushed_at': u'2016-06-22T17:37:11Z', u'has_issues': True, u'contents_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/contents/{+path}', u'events_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/events', u'contributors_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/contributors', u'updated_at': u'2016-06-22T13:14:15Z', u'trees_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/trees{/sha}', u'languages_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/languages', u'has_pages': False, u'git_url': u'git://github.com/andycasey/heroku-webhook-ping.git', u'id': 61547239, u'watchers_count': 0, u'milestones_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/milestones{/number}', u'git_tags_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/git/tags{/sha}', u'forks': 0, u'subscribers_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/subscribers', u'language': u'TeX', u'open_issues_count': 1, u'forks_count': 0, u'description': u'', u'issues_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/issues{/number}', u'watchers': 0, u'forks_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/forks', u'statuses_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/statuses/{sha}', u'subscription_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/subscription', u'default_branch': u'master', u'pulls_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/pulls{/number}'}, u'label': u'andycasey:new'}, u'additions': 2, u'statuses_url': u'https://api.github.com/repos/andycasey/heroku-webhook-ping/statuses/61b8b4de2d9c0327d66fcd660f2f39bf8736520a', u'merged_by': None}, u'action': u'reopened', u'sender': {u'organizations_url': u'https://api.github.com/users/andycasey/orgs', u'gists_url': u'https://api.github.com/users/andycasey/gists{/gist_id}', u'received_events_url': u'https://api.github.com/users/andycasey/received_events', u'html_url': u'https://github.com/andycasey', u'repos_url': u'https://api.github.com/users/andycasey/repos', u'gravatar_id': u'', u'starred_url': u'https://api.github.com/users/andycasey/starred{/owner}{/repo}', u'login': u'andycasey', u'avatar_url': u'https://avatars.githubusercontent.com/u/504436?v=3', u'id': 504436, u'followers_url': u'https://api.github.com/users/andycasey/followers', u'site_admin': False, u'events_url': u'https://api.github.com/users/andycasey/events{/privacy}', u'following_url': u'https://api.github.com/users/andycasey/following{/other_user}', u'subscriptions_url': u'https://api.github.com/users/andycasey/subscriptions', u'url': u'https://api.github.com/users/andycasey', u'type': u'User'}}


    trigger_event(gh_push)

    raise a

