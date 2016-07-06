
import logging
import github
import os


_HOOK_NAME = ".draft"

def synchronize(owner, repository, database):
    """
    Synchronize the state of a repository with our database.
    """

    # Get the state from GitHub first.
    repo = owner.get_repo(repository)

    # If no repo? Delete ours. #TODO

    # Check the hooks.
    i, hook_id, hooks = (0, 0, repo.get_hooks())
    while True:
        hook_page = hooks.get_page(i)
        if not hook_page: break

        for hook in hook_page:
            if  hook.active \
            and hook.config.get("url", None) == os.environ["HEROKU_URL"]:
                hook_id = hook.id
                break

        if hook_id > 0: break
        i += 1

    cursor = database.cursor()
    cursor.execute("SELECT * FROM repos WHERE id = %s", (repo.id, ))
    state = cursor.fetchone()

    # TODO: UPSERT
    if state is None:
        # Add the repository. 
        None

    else:
        None


def enable(owner, repository, database):
    """
    Enable a repository by adding a webhook on GitHub.

    :param owner:
        The owner of the repository.

    :param repository:
        The name of the repository to enable.

    :param database:
        A connection to the local database.
    """

    # Does the repository exist?
    repo = owner.get_repo(repository)

    # If the hook already exists, we will get a github.GithubException
    hook = repo.create_hook("web", events=["push", "pull_request"], config={
        "url": os.environ["HEROKU_URL"],
        "content_type": "json"
        })

    # Check this repository exists in our database?
    cur = database.cursor()
    cur.execute("SELECT name FROM repos WHERE id = %s", (repo.id, ))
    if not cur.fetchone:
        # Create the repository in the local directory.        
        cur.execute(
            """ INSERT INTO repos (id, user_id, name, hook_id)
                VALUES (%s, %s, %s, %s)""",
            (repo.id, owner.id, repo.name, hook.id))

    else:
        # Update the database with the hook id.
        cur.execute("UPDATE repos SET hook_id = %s WHERE id = %s",
            (hook.id, owner.id))

    database.commit()
    cur.close()

    return None



def disable(owner, repository, database):
    """
    Disable a repository by removing the webhook on GitHub.

    :param owner:
        The owner of the repository.

    :param repository:
        The name of the repository to disable.

    :param database:
        A connection to the local database.
    """

    repo = owner.get_repo(repository)

    # Get the hook ID from the database.
    cursor = database.cursor()
    cursor.execute("SELECT hook_id FROM repos WHERE id = %s", (repo.id, ))
    hook_id = cursor.rowcount()

    if hook_id > 0:
        hook = repo.get_hook(hook_id)
        hook.delete()

        cursor.execute(
            "UPDATE repos SET hook_id = %s WHERE id = %s", (0, repo.id))
        database.commit()

    else:
        logging.warn("Repository is already disabled.")

    cursor.close()
    return None


def sync_repositories(user, database):
    """
    Synchronize the list of repositories in the local database for the given
    user with what is listed on GitHub.

    :param user:
        The GitHub user.

    :param database:
        A connection to the local database.

    :returns:
        A four-length tuple containing: the total number of repositories, the 
        number of repositories that were added, the number of repositories that
        were updated, and the number of repositories that were deleted.
    """

    cursor = database.cursor()
    cursor.execute(
        """ SELECT id, regexp_replace(name, '\s+$', '') 
            FROM repos
            WHERE user_id = %s""",
        (user.id, ))
    local_repos = dict(cursor.fetchall() or {})

    # Now get information from GitHub.

    # Get all the repos.
    github_repos = {}
    i, repos = 0, user.get_repos()
    while True:
        repo_page = repos.get_page(i)
        if not repo_page: break

        github_repos.update(dict([(repo.id, repo.name) for repo in repo_page \
            if repo.owner.id == user.id]))
        i += 1

    # Find repositories that are not local.
    added = set(github_repos).difference(local_repos)
    for repo_id in added:
        logging.debug("Adding repo {0} ({1}) from user {2} ({3})".format(
            repo_id, github_repos[repo_id], user.id, user.name))

        cursor.execute(
            "INSERT INTO repos (id, user_id, name) VALUES (%s, %s, %s)",
            (repo_id, user.id, github_repos[repo_id]))

    # Find repositories with updated names.
    updated = [(d, k) for d, k in github_repos.items() if local_repos.get(d, k) != k]
    for repo_id, new_repo_name in updated:
        raise a
        logging.debug("Updating repo {0} with name '{1}' (from '{2}')".format(
            repo_id, new_repo_name, local_repos[repo_id]))
        cursor.execute("UPDATE repos SET name = %s WHERE id = %s",
            (new_repo_name, repo_id))

    # Delete any repositories that are no longer on GitHub.
    deleted = set(local_repos).difference(github_repos)
    for repo_id in deleted:
        logging.debug("Deleting repo {}".format(repo_id))
        cursor.execute("DELETE FROM repos WHERE id = %s", (repo_id, ))

    logging.debug("User {} ({}) added: {}, updated: {}, deleted: {}".format(
        user.id, user.name, len(added), len(updated), len(deleted)))

    cursor.close()

    return (len(github_repos), len(added), len(updated), len(deleted))



def repositories(database, user_ids=None, check_hooks=True):
    """
    Synchronize the repositories for a given set of user id(s).

    :param database:
        A database connection.

    :param user_ids: [optional]
        A single user id or a list-like of integers. If `None` is given then
        all users will be synchronized.

    :param check_hooks: [optional]
        Check the webhooks of each repository to see whether it is linked to the
        `.draft` application. If set to `False`, all new repositories will be
        assumed to be disabled.

    :returns:
        The number of repositories checked.
    """

    # Get all users.
    cursor = database.cursor()
    cursor.execute("SELECT id, token FROM users")
    users = cursor.fetchall()

    if users is None:
        # Ensure that the repos is also empty.
        cursor.execute("DELETE FROM repos")
        cursor.close()

        # Nothing to do.
        return 0

    N = 0
    for user_id, access_token in users:
        print("Synchronizing repositories from user {}".format(user_id))

        user = github.Github(login_or_token=access_token).get_user()

        # Get all the repos.
        i, repos = (0, user.get_repos())
        while True:
            repo_page = repos.get_page(i)
            if not repo_page: break

            for repo in repo_page:
                # Only synchronize repositories that the user owns.
                if repo.owner.id != user.id:
                    continue

                data = {
                    "user_id": user.id,
                    "repo_id": repo.id,
                    "name": repo.name,
                }
                print(data)

                # Check if the repository already exists in the database.
                cursor.execute(
                    "SELECT user_id, hook_id FROM repos WHERE id = %s",
                    (repo.id, ))

                # Add the repository if it doesn't exist.
                if not cursor.rowcount:
                    print("Added")
                    cursor.execute(
                        """ INSERT INTO repos (id, user_id, name)
                            VALUES (%(repo_id)s, %(user_id)s, %(name)s)""",
                        data)

                elif check_hooks:
                    # TODO remove this?


                    # Check for hooks?
                    j, hooks, enabled = (0, repo.get_hooks(), False)
                    while True:
                        hook_page = hooks.get_page(j)
                        if not hook_page: break

                        for hook in hook_page:
                            if  hook.config.get("url", None) \
                                    == os.environ["HEROKU_URL"] \
                            and hook.active:
                                enabled = True
                                break

                        if enabled: break
                        j += 1

                    print("hoooks", enabled)
                    data.update(enabled=enabled)
                    cursor.execute(
                        """UPDATE repos SET     user_id = %(user_id)s,
                                                name = %(name)s,
                                                webhook_enabled = %(enabled)s
                                        WHERE   id = %(repo_id)s""",
                        data)

                N += 1
            i += 1

    cursor.close()
    database.commit()

    print("Updated {} repositories".format(N))
    return N
