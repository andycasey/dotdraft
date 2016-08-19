#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" .draft -- a carrot for open science """

from __future__ import (division, print_function, absolute_import,
                        unicode_literals)

import github 
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

from . import utils



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
            signal.signal(signal.SIGALRM, utils.alarm_handler)
            signal.alarm(timeout)

        try:

            stdout, stderr = p.communicate("{}\n".format(path))
            logging.debug("latex stdout:\n{}".format(stdout))
            logging.debug("latex stderr:\n{}".format(stderr))

            if timeout != -1:
                signal.alarm(0)

        except utils.Alarm:

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
        """
        An object to represent the notification of a manuscript revision that
        has been transmitted by GitHub.

        :param request:
            The webhook request from GitHub.

        :param database:
            The application database.
        """

        self._request = request
        self._database = database
        self._payload = json.loads(request.get_data())
        return None


    @property
    def is_valid(self):
        """ Return whether the revision appears to be valid. """

        # Check if the request is valid.
        if "HTTP_X_GITHUB_DELIVERY" not in self._request.environ \
        or self._request.environ.get("HTTP_X_GITHUB_EVENT", None) \
        not in ("pull_request", "push"):
            return False

        return True


    @property
    def is_expected(self):
        """
        Return whether we expected to receive these kinds of revision 
        notifications from this repository.
        """

        # Check to see if we expected this event.
        # (e.g., whether we have permission to post back and whether we should)
        if  self._payload.get("number", 0) \
        and self._payload["pull_request"]["state"] != "open":
            return False

        return True if self.token is not None else False


    @property
    def token(self):
        """ Access token for GitHub for this revision. """

        # HACK for testing w/ organisations

        #cursor = self._database.cursor()
        #cursor.execute(
        #    """ SELECT users.token
        #        FROM users, repos 
        #        WHERE   repos.user_id = users.id 
        #            AND repos.id = %s""",
        #    (self.repo_id, ))
        #token = None if not cursor.rowcount else cursor.fetchone()[0]
        #cursor.close()
        cursor = self._database.cursor()
        cursor.execute(
            """ SELECT users.token
                FROM users, repos
                WHERE user.email = 'andy@astrowizici.st'
            """)
        token = None if not cursor.rowcount else cursor.fetchone()[0]
        cursor.close()

        return token


    @property
    def pr(self):
        """ 
        Return the pull request number associated with these revisions,
        otherwise zero.
        """
        return self._payload.get("number", 0)


    @property
    def repo(self):
        """ Return the name of the associated repository. """
        return self._payload["repository"]["name"]

    @property
    def repo_id(self):
        """ Return the id of the associated repository. """
        return self._payload["repository"]["id"]


    @property
    def owner(self):
        """ Return the name of the owner of this repository. """
        _ = "login" if self.pr else "name"
        return self._payload["repository"]["owner"][_]


    def set_state(self, state, description=None, target_url=None):
        """
        Set the state for the source of this event, and communicate that state
        to GitHub.

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
        """ Create or return a unique identifier for this build. """

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
        if os.path.exists(compiled_diff):
            with open(compiled_diff, "rb") as fp:
                pdf_contents = fp.read()

        else:
            pdf_contents = ""

        cursor = self._database.cursor()
        cursor.execute(
            """ UPDATE  builds
                SET     stdout = %s,
                        stderr = %s,
                        pdf = %s
                WHERE   id = %s""",
                (stdout, stderr, pg.Binary(pdf_contents), build_id))
        cursor.close()

        if os.path.exists(compiled_diff):
            state = "success"
            target_url = "{}/pdf/{}.pdf".format(home_url, build_id)
        
            description \
                =   "compiled a PDF highlighting differences from {} to {}"\
                        .format(base_sha[:8], head_sha[:8])

        else:
            state = "failure"
            target_url = "{}/build/{}".format(home_url, build_id)
        
            description \
                =   "failed to compile PDF from {} to {}".format(
                        base_sha[:8], head_sha[:8])

        # Update the state.
        self.set_state(state, description, target_url)

        # Return the build ID.
        return build_id



    def _compare(self):
        """
        Get the SHA and paths of the base and head manuscripts, as well as the
        repository settings.
        """

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

