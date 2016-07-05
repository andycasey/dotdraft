
import github
import os



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


    # Does the repository exist?
    repo = user.get_repo(repository) # TODO: if it doesn't?
    
    raise a
    # Create a webhook.
    repo.cr

    # Update hook id in the database.

    # Is this repository in the database? If it is, set it as enabled.
    # Otherwise, create it.

    return True



def disable(owner, repository, database, sync=True):

    repo = owner.get_repo(repository) # What if it doesn't exist?!

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

        return True

    elif sync:
        synchronize(owner, repository, database)
        disable(owner, repository, database, sync=False)

    else:
        logging.warn("Repository is already disabled.")

    return True


def sync_repositories(user, database):

    cursor = database.cursor()
    cursor.execute("SELECT id, name FROM repos WHERE user_id = %s", (user.id))
    local_repos = cursor.fetchall() or {}



    # Now get information from GitHub.

    # Get all the repos.
    origin_repos = {}
    i, repos = 0, user.get_repos()
    while True:
        repo_page = repos.get_page(i)
        if not repo_page: break

        origin_repos.update(dict([(repo.id, repo.name) for repo in repo_page \
            if repo.owner.id == user.id]))




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