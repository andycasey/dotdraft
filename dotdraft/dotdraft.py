#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" .draft -- a carrot for open science """

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)


import json
import logging
import os
import psycopg2 as pg
import requests
import signal
import subprocess
import yaml
from collections import deque
from re import search as re_search
from tempfile import mkdtemp

# This is so dumb.
import github 
#import pygithub3 as pygithub

from . import utils

GH_TOKEN = os.environ["GH_TOKEN"]
HEROKU_URL = os.environ["HEROKU_URL"] # There must be a better way..

# General utilities.
class Alarm(Exception):
    pass

def alarm_handler(signum, frame):
    raise Alarm



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
        # TODO:
        REQUIRE_DD_IN_COMMIT_FOR_TRIGGER = False
        if REQUIRE_DD_IN_COMMIT_FOR_TRIGGER:
            return (None, after_hash)
        else:
            return (prev_hash, after_hash)

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

    diff_path = utils.get_unused_filename(repository_path, suffix=".diff.tex")

    # Execute latexdiff given some acceptable keywords.
    # TODO: allow keywords to get passed through here.
    command = './dotdraft/latexdiff "{}" "{}" > "{}"'.format(
        old_path, new_path, diff_path)
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

    commands = [kwargs["latex"]]#, kwargs["latex"], kwargs["latex"]]
    for command in commands:

        p = subprocess.Popen([command], cwd=os.path.dirname(path),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, shell=True)

        if timeout != -1:
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(timeout)

        try:

            stdout, stderr = p.communicate("{}\n".format(path))
            logging.debug("latex stdout:\n{}".format(stdout))
            logging.debug("latex stderr:\n{}".format(stderr))

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
    compiled_pdf = os.path.join(os.path.dirname(path),
        os.path.basename(os.path.extsep.join([base_path, "pdf"])))

    return (compiled_pdf, stdout, stderr)




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
    before_basename = "{}.tex".format(utils.random_string())
    while os.path.exists(os.path.join(repository_path, before_basename)):
        before_basename = "{}.tex".format(utils.random_string())

    # TODO FAIL
    r = git("show {}:{} > {}".format(
            before_hash, os.path.basename(manuscript_basename), before_basename),
        cwd=repository_path)

    return os.path.join(repository_path, before_basename)



class Revision(object):

    _context = ".draft"
    _default_description = {
        "error": "Build failed. Please open an issue on andycasey/dotdraft",
        "pending": "Compiling PDF with changes highlighted",
        "success": "PDF compiled successfully",
        "failure": "Could not compile the PDF"
    }


    def __init__(self, request, database):

        self._request = request
        self._database = database
        self._payload = json.loads(request.get_data())


        return None


    @property
    def is_valid(self):

        # Check if the request is valid.
        if "HTTP_X_GITHUB_DELIVERY" not in self._request.environ \
        or self._request.environ.get("HTTP_X_GITHUB_EVENT", None) \
        not in ("pull_request", "push"):
            return False

        return True


    @property
    def is_expected(self):

        # Check to see if we expected this event.
        # (e.g., whether we have permission to post back and whether we should)
        if  self._payload.get("number", 0) \
        and self._payload["pull_request"]["state"] != "open":
            return False

        return True if self.token is not None else False


    @property
    def token(self):
        """ Access token for GitHub for this revision. """

        cursor = self._database.cursor()
        cursor.execute("SELECT token FROM users LIMIT 1")
        token = None if cursor.rowcount == 0 else cursor.fetchone()[0]
        cursor.close()

        return token


    @property
    def pr(self):
        return self._payload.get("number", 0)


    @property
    def repo(self):
        return self._payload["repository"]["name"]


    @property
    def owner(self):
        _ = "login" if self.pr else "name"
        return self._payload["repository"]["owner"][_]




    def set_state(self, state, description=None, target_url=None):
        """
        Set the GitHub state for the source of this event.

        :param state:
            Must be one of either: pending, error, success, or failure.

        :param description: [optional]
            The description for the state. If `None` is given, then the default
            description for the `state` will be set.

        :param target_url: [optional]
            The URL to access more details about the state. If `None` is given
            then the default application URL will be set.

        :returns:
            Boolean flag as to whether the state was changed.
        """

        state = state.strip().lower()
        available_states = ("pending", "error", "success", "failure")
        if state not in available_states:
            raise ValueError("state must be one of: {}".format(
                ", ".join(available_states)))

        # Update database with state.
        cursor = self._database.cursor()
        cursor.execute("UPDATE builds SET state = %s WHERE id = %s",
            (state, self.build_id))
        cursor.close()

        if state == "pending" and not self.pr:
            return False

        description = description or self._default_description[state]
        target_url = target_url or os.environ["HEROKU_URL"]

        # Authenticate with GitHub
        gh = github.Github(login_or_token=self.token)
        repository = gh.get_repo("/".join([self.owner, self.repo]))
            
        if self.pr:

            # Update status on pull request.
            pr = repository.get_pull(self.pr)
            commit = deque(pr.get_commits(), maxlen=1).pop()
            commit.create_status(state, description=description, 
                target_url=target_url, context=self._context)

        else:
            # Add comment to commit.
            commit = repository.get_commit(self._payload["after"])
            commit.create_comment(
                "`.draft {}`: [{}]({})".format(state, description, target_url))

        return True


    @property
    def build_id(self):

        if not hasattr(self, "_build_id"):
            cur = self._database.cursor()
            cur.execute(
                """ INSERT INTO builds (user_id, repo_id, state) 
                    VALUES (0, 0, 'init') RETURNING id""")
            build_id = cur.fetchone()[0]

            self._database.commit()
            cur.close()
            self._build_id = build_id

        return self._build_id



    def build(self, **kwargs):
        """
        Compile a PDF that highlights the differences in this revision.
        """

        # Get a build ID.
        build_id = self.build_id

        self.set_state("pending")
        home_url = os.environ["HEROKU_URL"]
        
        # Get the comparisons.
        base_sha, head_sha, base_path, head_path, settings = self._compare()

        if head_path is None and head_sha is None:
            return ("success", "No manuscript found: no PDF produced", home_url)

        elif base_path is None and base_sha is None:
            return ("success", "No base SHA found: no PDF produced", home_url)

        # Load the settings.

        # Run difftex on the before and after.
        manuscript_diff = latexdiff(base_path, head_path, **settings)

        # Compile the manuscript_diff file.
        # Copy the ulem.sty file into that dir first. # TODO
        os.system("cp {0} {1}/{0}".format("ulem.sty", os.path.dirname(manuscript_diff)))
        compiled_diff, stdout, stderr = latex(manuscript_diff, **settings)

        # Save the compiled_diff, stdout and stderr to the database as a new
        # build and return the build id.
        try:
            with open(compiled_diff, "rb") as fp:
                pdf_contents = pg.Binary(fp.read())

        except OSError:
            pdf_contents = None

        cursor = self._database.cursor()
        cursor.execute(
            """ UPDATE  builds
                SET     stdout = %s,
                        stderr = %s,
                        pdf = %s
                WHERE   id = %s""",
                (stdout, stderr, pdf_contents, build_id))
        cursor.close()

        if os.path.exists(compiled_diff):
            state = "success"
            target_url = "{}/pdf/{}.pdf".format(home_url, build_id)
        
            description \
                =   "compiled a PDF highlighting differences from {} to {}"\
                        .format(base_sha[:8], head_sha[:8])

        else:
            state = "failure"
            target_url = "{}/build/{}.log".format(home_url, build_id)
        
            description \
                =   "failed to compile PDF from {} to {}".format(
                        base_sha[:8], head_sha[:8])

        # Update the state.
        self.set_state(state, description, target_url)

        # Return the build ID.
        return build_id



    def _compare(self):

        payload = self._payload

        if self.pr:
            # Pull request triggered the webhook.
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

            if manuscript_basename is None:
                return (None, None, None, None, settings)

            # Get the paths.
            base_path = os.path.join(base_repository, manuscript_basename)
            head_path = os.path.join(head_repository, manuscript_basename)
            logging.debug("Comparing paths {} with {}".format(base_path, head_path))

            # Keep the SHAs.
            head_sha = payload["pull_request"]["head"]["sha"]
            base_sha = payload["pull_request"]["base"]["sha"]
            logging.debug("Comparing SHAs {} with {}".format(base_sha, head_sha))


        else:

            # Clone the repository.
            repository_path = clone_repository(payload)

            # Get the manuscript paths.
            settings = load_settings(repository_path)

            # Check the commit message for a previous SHA.
            base_sha, head_sha = get_commit_comparisons(payload, repository_path)

            if base_sha is None:
                logging.info("No base SHA found; nothing to do.")
                return (None, head_sha, None, None, settings)

                
            # What is the name of the manuscript?
            manuscript_basename =  settings.get("manuscript", None) \
                                or get_manuscript_path(repository_path)

            if manuscript_basename is None:
                logging.info("No manuscript found.")
                return (None, None, None, None, settings)
    
            # base = original; head = changed
            head_path = os.path.join(repository_path, manuscript_basename)
            base_path = copy_previous_manuscript(
                repository_path, base_sha, manuscript_basename)
        
        return (base_sha, head_sha, base_path, head_path, settings)



def webhook(request, database=None, **kwargs):
    """
    Method to run when GitHub has triggered an event on a repository.

    :param request:
        A WSGI request, which might have come from GitHub.

    :param database: [optional]
        A Postgres database to store compiled PDFs in. If `None` is supplied,
        then files will be uploaded to a temporary site.
    """

    status_context = kwargs.pop(
        "status_context", ".draft")
    pending_description = kwargs.pop(
        "pending_description", "compiling your differenced PDF")

    logging.info("Received webhook: {}".format(type(request)))

    # Check the request is from GitHub, otherwise do nothing.
    if not is_valid_github_request(request):
        logging.info("Not valid GitHub request. Ignoring.")
        return False

    payload = json.loads(request.get_data())
    pull_request = payload.get("number", 0)
    repo = payload["repository"]["name"]
    owner = payload["repository"]["owner"]["login" if pull_request else "name"]

    # TODO: Log the valid request in the DB

    # Update status to pending.
    if pull_request and payload["pull_request"]["state"] == "open":

        # Update status.
        gh = github.Github(login_or_token=GH_TOKEN)
        pr = gh.get_repo("/".join([owner, repo])).get_pull(pull_request)
        commit = deque(pr.get_commits(), maxlen=1).pop()

        commit.create_status("pending", target_url=HEROKU_URL,
            description=pending_description, context=status_context)

        logging.info("Updated status context on {}/{}/{}: {} - {}".format(
            owner, repo, pull_request, status_context, pending_description))

    elif pull_request:
        logging.info("Webhook triggered by closed pull request. Ignoring.")
        return None

    else:
        logging.info("Webhook triggered by commit(s)")
        

    # Authenticate with GitHub.
    gh = pygithub.Github(token=GH_TOKEN)
    

    # Run the difference between two LaTeX files.
    if not pull_request:

        # Clone the repository.
        repository_path = clone_repository(payload)

        # Get the manuscript paths.
        settings = load_settings(repository_path)

        # Check the commit message for a previous SHA.
        base_sha, head_sha = get_commit_comparisons(payload, repository_path)

        # Create the payload for comment that will go back to GitHub.
        comment_response = gh.repos.commits.create_comment
        paths = payload["commits"][-1]["added"] + payload["commits"][-1]["modified"]
        
        print(payload)

        comment_payload = {
            "commit_id": head_sha,
            "position": 1,
            "line": 1,
            "path": paths[0]
        }
        commit_kwds = {
            "sha": head_sha,
            "user": owner,
            "repo": repo
        }

        if base_sha is None:
            logging.info("No base SHA found; nothing to do.")

            # We need a path file to compare against. So just get the first one
            # from added/modified.
            comment_payload.update({
                "body": "`.draft`: No base commit found to compare against."
            })
            comment_response(comment_payload, **commit_kwds)
            return None

        # What is the name of the manuscript?
        manuscript_basename =  settings.get("manuscript", None) \
                            or get_manuscript_path(repository_path)

        if manuscript_basename is None:
            logging.info("No manuscript found.")
            comment_payload.update({
                "body": "`.draft`: No manuscript (`*.tex`) found in repository."
            })
            comment_response(comment_payload, **commit_kwds)
            return None

        else:
            comment_payload["path"] = manuscript_basename

        # base = original; head = changed
        head_path = os.path.join(repository_path, manuscript_basename)
        base_path = copy_previous_manuscript(
            repository_path, base_sha, manuscript_basename)
    
        uri = "{owner}.{repo}.{base}..{head}.pdf".format(owner=owner,
            repo=repo, base=base_sha[:8], head=head_sha[:8])


    else:

        pr_response = commit.create_status
        pr_kwds = {
            #"state"
            #"description"
            "target_url": HEROKU_URL,
            "context": status_context,
        }

        # Pull request triggered the webhook.
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

        if manuscript_basename is None:
            logging.info("No manuscript found.")

            pr_kwds.update({
                "state": "success",
                "description": "No manuscript found; skipped PDF creation."
            })
            pr_response(**pr_kwds)
            return None


        # Get the paths.
        base_path = os.path.join(base_repository, manuscript_basename)
        head_path = os.path.join(head_repository, manuscript_basename)
        logging.debug("Comparing paths {} with {}".format(base_path, head_path))

        # Keep the SHAs.
        head_sha = payload["pull_request"]["head"]["sha"]
        base_sha = payload["pull_request"]["base"]["sha"]
        logging.debug("Comparing SHAs {} with {}".format(base_sha, head_sha))

        uri = "{owner}.{repo}.{issue}.pdf".format(
            owner=owner, repo=repo, issue=payload["number"])


    # Run difftex on the before and after.
    manuscript_diff = latexdiff(base_path, head_path, **settings)

    # Compile the manuscript_diff file.
    # Copy the ulem.sty file into that dir first.
    os.system("cp {0} {1}/{0}".format("ulem.sty", os.path.dirname(manuscript_diff)))
    compiled_diff, stdout, stderr = latex(manuscript_diff, **settings)

    # Check things were OK.
    if not os.path.exists(compiled_diff):
        logging.warn("No compiled diff file found.")
        

        message =   "Something went wrong when trying to compile the PDF "\
                    "between `{}` and `{}`:\n\n"\
                    "````\n"\
                    "{}"\
                    "````\n".format(base_sha[:8], head_sha[:8], stdout)

        if pull_request:
            pr_kwds.update({
                "state": "failure",
                "description": "Failed to compile PDF. See error log."
            })
            pr_response(**pr_kwds)

            # Comment on the PR.
            gh.issues.comments.create(pull_request, message, 
                user=owner, repo=payload["repository"]["name"])

        else:
            # Comment on the commit.
            comment_payload["body"] = message
            comment_response(comment_payload, **commit_kwds)
            
        return None


    # Upload the PDF or store it.
    logging.info("Created diff PDF successfully: {}".format(compiled_diff))
    if database is None:
        logging.warn("No database supplied. Using transfer.sh instead..")

        upload_response = requests.put(
            url="https://transfer.sh/{}".format(uri),
            data=open(compiled_diff, "rb"))

        if upload_response.status_code == 200:
            target_url = upload_response.text.strip()
            logging.info("Compiled PDF uploaded successfully to {}".format(
                target_url))

            # Depending on whether we are in a PR or not, the behaviour will be
            # different on what to do with the target_url.

        else:
            logging.warn("Upload failed: {}".format(
                upload_response.status_code))

            pr_kwds.update({
                "state": "failure",
                "description": "Failed to upload compiled PDF [{}]".format(
                    upload_response.status_code)
            })
            pr_response(**pr_kwds)
            return None
            
        warning_message \
            =   "\n\n\n"\
                "**Warning:** The link to the compiled PDF from `.draft` is "\
                "**not** persistent and will expire in two weeks. Please set"\
                " up `.draft` with a free Postgres database to enable "\
                "persistent links."
    else:
        warning_message = ""
        raise NotImplementedError("db not set up yet")



    # Code here is only executed if we have a target_url and the PDF was stored
    # *somewhere* (either retrievable via database or from transfer.sh)
    if pull_request:
        pr_kwds.update({
            "state": "success",
            "target_url": target_url,
            "description": \
                "compiled a PDF highlighting differences from {} to {}"\
                .format(base_sha[:8], head_sha[:8])
        })
        pr_response(**pr_kwds)

        if warning_message is not None and warning_message != "":
            gh.issues.comments.create(pull_request, warning_message.lstrip(),
                user=owner, repo=payload["repository"]["name"])

    else:
        comment_payload["body"] \
            =   "`.draft`: Compiled a PDF highlighting differences from {} to "\
                "{}: [{}]({}){}".format(
                    base_sha[:8], head_sha[:8], uri, target_url, warning_message)
        comment_response(comment_payload, **commit_kwds)

    return True


