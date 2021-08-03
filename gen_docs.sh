#!/bin/zsh

documentation build 'src/**' -f html --config documentation.yml -o docs/api_docs_html
documentation build 'src/**' -f md --config documentation.yml -o api_docs.md
doctoc README.md