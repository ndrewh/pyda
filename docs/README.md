# Pyda Documentation

This directory contains the documentation for Pyda, built using [MkDocs](https://www.mkdocs.org/) with the [Material theme](https://squidfunk.github.io/mkdocs-material/).

## Building the Documentation

### Prerequisites

Install the documentation dependencies:

```bash
pip install -r requirements.txt
```

### Local Development

To serve the documentation locally with live reload:

```bash
mkdocs serve
```

This will start a local server at `http://127.0.0.1:8000` where you can preview the documentation. Changes to markdown files will automatically reload the page.

### Building Static Site

To build the static HTML files:

```bash
mkdocs build
```

The built site will be in the `site/` directory.

## Documentation Structure

- `mkdocs.yml` - Main configuration file
- `index.md` - Homepage
- `getting-started/` - Installation and quick start guides
- `api/` - API reference documentation (auto-generated from docstrings)
- `examples/` - Code examples and tutorials

## API Documentation

The API documentation is automatically generated from docstrings in the source code using [mkdocstrings](https://mkdocstrings.github.io/). When you update docstrings in the Python source files, the documentation will automatically reflect those changes.

## GitHub Actions

The documentation is automatically built and deployed via GitHub Actions:

- **Build**: Runs on every push and pull request
- **Deploy**: Automatically deploys to GitHub Pages on pushes to main/master
- **Artifacts**: Creates downloadable zip/tarball archives of the built site

## Contributing

When contributing to the documentation:

1. Test locally with `mkdocs serve`
2. Ensure all links work and code examples are correct
3. Follow the existing style and structure
4. Update docstrings in the source code for API changes

The documentation uses Google-style docstrings. See the existing code for examples. 