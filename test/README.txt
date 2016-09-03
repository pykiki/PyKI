###############################################
### to keep for later use, do not take care ###
###############################################

# tests auto: tox
pip install tox
# conf a mettre a la racine du projet
cat > "/Users/albookpro/github/PyKI/tox.ini" << "EOF"
[tox]
envlist = py27, py26, py35
[testenv]
install_command = pip install {opts} {packages}
deps = -r{toxinidir}/requirements.txt
commands = {toxinidir}/test/test-UseCase.py
EOF

# lancer le test
cd /Users/albookpro/github/PyKI/
tox

# test syntaxe python (norme pep8)
pip install flake8
find test/ -iname '*.py' | xargs flake8 --show-source
