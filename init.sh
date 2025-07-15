#!/bin/bash

brew install syft
brew install cyclonedx/cyclonedx/cyclonedx-cli
brew tap anchore/grype
brew install grype

npx @cyclonedx/cdxgen -h




