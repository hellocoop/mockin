#!/bin/bash

# ChatGPT generated

# Check if jq is installed
if ! command -v jq &> /dev/null
then
    echo "jq could not be found. Please install jq to continue."
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker could not be found. Please install Docker to continue."
    exit 1
fi

# Check if the repository is clean (no uncommitted changes)
if ! git diff-index --quiet HEAD --; then
    echo "The repository has uncommitted changes. Please commit or stash them before proceeding."
    exit 1
fi

# Extract version from package.json using jq
VERSION=$(jq -r '.version' package.json)

# Docker details
DOCKER_USERNAME="hellocoop"  
DOCKER_IMAGE_NAME="mockin"  
DOCKER_TAG="$DOCKER_USERNAME/$DOCKER_IMAGE_NAME"

# NPM package name
NPM_PACKAGE_NAME="@hellocoop/mockin"

# Get the latest published version of the npm package
PUBLISHED_VERSION=$(npm view $NPM_PACKAGE_NAME version)

# Compare the versions
if [ "$VERSION" = "$PUBLISHED_VERSION" ]; then
    echo "Current version is the same as the published version. Incrementing the version."

    # Increment the version using npm version patch
    npm version patch

    # Update VERSION variable to new version
    VERSION=$(jq -r '.version' package.json)

    echo "New version: $VERSION"

    # Commit and push the changes to the repository
    git add package.json
    git commit -m "Increment version to $VERSION"
    git push origin main

    echo "Updated package.json has been pushed to the repository."
fi

# Building Docker image
echo "Building Docker amd64 and arm64 image with tag: $VERSION and pushing to Docker Hub"
docker buildx build --platform linux/amd64,linux/arm64 -t "$DOCKER_TAG:latest" -t "$DOCKER_TAG:$VERSION" . --push

# # Pushing the image to Docker Hub
# echo "Pushing latest tag to Docker Hub"
# docker push "$DOCKER_TAG:latest"

# echo "Pushing version $VERSION tag to Docker Hub"
# docker push "$DOCKER_TAG:$VERSION"

# Publish to npm
echo "Publishing version $VERSION to npm"
npm publish

echo "Publishing complete"
