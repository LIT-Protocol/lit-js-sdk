#!/bin/zsh

documentation build src/** -f html --config documentation.yml -o docs_html
documentation build src/** -f md --config documentation.yml -o docs_md