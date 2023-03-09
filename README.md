# Crypt4GH Re-encryptor

## Main installation instructions

- Install Poetry:
  - `curl -sSL https://install.python-poetry.org | python3 -`
- Install Python 3.10 through e.g. Conda, or directly in your IDE:
  - `conda create -env myenv python=3.10`
  - `conda activate myenv`
- Install dependencies:
  - `poetry install --with dev --no-root`

## For mypy support in PyCharm

- In PyCharm, install "Mypy" plugin (not "Mypy (Official)")
  - `which mypy` to get path to mypy binary
  - In the PyCharm settings for the mypy plugin:
    - Select the mypy binary 
    - Select `pyproject.toml` as the mypy config file

## For automatic formatting and linting

I have added my typical setup for automatic formatting and linting. The main alternative is to use black, which is easier to set up, but it does not have as many options. I am not fully happy with my config, but I at least like it better than black. 

- In PyCharm -> File Watchers:
  - Click arrow down icon
  - Select `watchers.xml`
