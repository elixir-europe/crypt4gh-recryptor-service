# Contributing to omnipy development

## Development setup

- Install uv:
  - `curl -LsSf https://astral.sh/uv/install.sh | sh`

- Install dependencies:
  - `uv sync --group dev`

- Update all dependencies:
  - `uv lock --upgrade`

- Update single dependency, e.g.:
  - `uv lock --upgrade-package prefect`

- If a dependency is not updated to the latest version available, you might need to clear the
  uv cache:
  - `uv cache clean`

### For mypy support in PyCharm

- In PyCharm, install "Mypy" plugin (not "Mypy (Official)")
  - `which mypy` to get path to mypy binary
  - In the PyCharm settings for the mypy plugin:
    - Select the mypy binary 
    - Select `pyproject.toml` as the mypy config file

### For automatic formatting and linting

The setup for automatic formatting and linting is rather complex. The main alternative is to use 
black, which is easier to set up, but it does not have as many options and the main omnipy developer
is opinionated against the default black setup. The yapf config is not fully
defined. 

- To install git hooks that automagically format and lint before every commit:
  - `uv run pre-commit install`

- In PyCharm -> File Watchers:
  - Click arrow icon pointing down and to the left
  - Select `pycharm_file_watchers.xml`
