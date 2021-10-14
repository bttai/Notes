

```shell
echo "# Notes" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin git@github.com:bttai/Notes.git
git push -u origin main
```

# New PC
```shell
#.ssh/config
Host github.com
        HostName github.com
        User git
        Port 22
        IdentityFile ~/.ssh/id_rsa_github
chmod 600 ~/.ssh/id_rsa_github

ssh-add ~/.ssh/id_rsa_github

git config --global user.name "Tan Tai Bui"
git config --global user.email "bttai@yahoo.fr"
git init
git remote add origin git@github.com:bttai/Notes.git
git branch -M main
git fetch origin main
git merge origin/main

```

#Before work

```shell
git checkout main
git fetch origin main
git merge origin/main
```
#Commit modifications

```shell
git add .
git commit -m "Message"

```
#Conflit modifications
```shell

git fetch origin main
git diff main..origin/main
git commit -m "Resolution ..."

```

#Push

```shell
git push -u origin main
```
```shell
--allow-unrelated-histories
```

# git config

```shell

git config --global user.name "Tan Tai Bui"
git config --global user.email "bttai@yahoo.fr"

```

# git init

```shell

git init

# créer nouveaux fichiers

touch notes.md
touch confict.md
touch draft.md
touch test.md
touch trash.md

```

# Enregistrer des modifications

```shell

# commener à suivre des fichiers
git add *.md
git add README
git commit -m "initial project version"

# supprimer un fichier de l'index
git rm --cached draft.md

# supprimer un fichier
git rm draft.md

# déplacer un fichier
git mv draft.md doc.md

# enregistrer toutes modifications
git add .
git commit -m "first modification"

# modifier dernier commit
git commit --amend -m "first modification"

```

# Annuler des modifications

```shell

# récupérer la dernière version du fichier
git checkout -- test.md

# désindexer un fichier
git reset HEAD test.md

# récupérer une ancienne version
git checkout 1f31b59 -- test.md

# récupérer un document dans une ancienne version
git checkout 1f31b59 --test.md
git commit -am "second modification"

# revenir à une version précédante
git revert  823b1b1

# récupérer tous les fichiers à la version 676cd94
git reset --hard 676cd94

# récupérer un fichier à la version 1112b85
git reset 1112b85  notes.md
git checkout -- notes.md

# voir des fichiers non indexés
git clean -n
# supprimer des fichiers non indexés
git clean -f

```

# Navigating the commit tree

```shell

# git ls-tree
git ls-tree HEAD
git ls-tree HEAD^
git ls-tree main
git ls-tree 676cd94^^^

# git log
git log
--oneline
--since="yyyy-mm-dd"
--until="yyyy-mm-yy"
--author="yyyy-mm-yy"
--grep="authentification"
-p --> more detail about the commit
-n --> n last commits
git log --stat --summary --oneline -3
git log --oneline --graph --all --decorate

```

# Comparing commits

```shell

git diff
--stat
--summary
-b --ignore-space-change
-w --ignore-all-space
--color-words

```
# Branching

```shell

# créer une nouvelle branche
git branch dev

# liste des branches
git branch

# changer de branche
git checkout dev

#créer et changer de branch
git checkout -b dev

# lister des branches contient la branche en cours
git branch --merge

```
# Merge

```shell

# merge la branche dev
git checkout main
git merge dev

# si conflict
git merge dev
# modifier des fichiers confict
git add .
git commit

```

# Connexion au github

[https://docs.github.com/en/github/authenticating-to-github/adding-a-new-ssh-key-to-your-github-account]:https://docs.github.com/en/github/authenticating-to-github/adding-a-new-ssh-key-to-your-github-account

# Create a new repository on GitHub

```shell

echo "# github" >> README.md
git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin git@github.com:bttai/github.git
git push -u origin main

```

# push an existing repository from the command line

```shell

git remote add origin git@github.com:bttai/github.git
git branch -M main
git push -u origin main

```

# git clone

```shell

git clone git@github.com:bttai/github.git local_repertory
git log --oneline
git status

```

# Remote

```shell

# view remote branch
git branch -r

# branches : local + remote
git branch -a

# log
git log --oneline origin/main

# fetch
git fetch origin/main
```
# Basic guidelines

- fetch before work
- fetch before push
- fetch often

# merging in fetched changes

```shell
    
# compare
git fetch origin
git diff origin/main..main

# merge
git merge origin/main

# pull
git pull = git fetch + git merge

# push
git push -u origin main


```

# Checking out remote branch


```shell
    
git branch dev origin/dev


```

# Push to the remote server


```shell

git branch main
git fetch orgine
git merge origin/main
git push -u orgin main


```

# Deleting remote branch

```shell

# push to origin nothing up to the branch branch_to_delete
git push origin :branch_to_delete

# or
git push origin --delete branch_to_delete

```

# Collaboration workflow

## My work

```shell

git checkout main
git fetch
git merge origin/main

git checkout -b feedback_form
git add feedback.html
git commit -m "Add custumer feedback form"

git fetch
git push -u origin feedback_form

```
## My coworker's work

```shell

# good practice
git checkout main
git fetch
git merge origin/main

#
git branch -a
git checkout -b feedback_form origin/feedback_form
git log
git show a9e9b387
# after modified the page
git commit -am "Add tour selector to feedback form"

git fetch
git push

```


## My work

```shell
 
# good practice
git checkout feedback_form
git fetch
git log -p feedback_form..origin/feedback_form
git merge origin/feedback_form

# check main branch
git checkout main
git fetch
git diff main..origin/main

# update main branch
git merge origin/main

# push to remote server
git push


```

# Use cas

## Copy files between Git branches

ref : [https://xliska.wordpress.com/2010/09/22/copy-files-between-git-branches/](https://xliska.wordpress.com/2010/09/22/copy-files-between-git-branches/)


```shell
# use the `git show` command:
$ git show <branch_name>:path/to/file >path/to/local/file

#use the `git checkout` command:
$ git checkout <branch_name> path/to/new/file


```

