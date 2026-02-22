#!/bin/bash
set -e

# Usage: npm run release [patch|minor|major]
# Defaults to "patch" if no argument given.
# Bumps version, commits, tags, pushes, and creates a GitHub Release
# which triggers the CI/CD workflow to publish to npm and Docker Hub.

BUMP="${1:-patch}"

if [[ "$BUMP" != "patch" && "$BUMP" != "minor" && "$BUMP" != "major" ]]; then
    echo "Usage: npm run release [patch|minor|major]"
    exit 1
fi

# Check for clean working tree
if ! git diff-index --quiet HEAD --; then
    echo "Error: uncommitted changes. Please commit or stash them first."
    exit 1
fi

# Check we're on main
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
    echo "Error: must be on main branch (currently on $BRANCH)"
    exit 1
fi

# Check gh CLI is available
if ! command -v gh &> /dev/null; then
    echo "Error: gh CLI not found. Install it: https://cli.github.com"
    exit 1
fi

# Run tests first
echo "Running tests..."
npm test

# Bump version (updates package.json + package-lock.json, creates git tag)
echo "Bumping $BUMP version..."
npm version "$BUMP"

VERSION=$(node -p "require('./package.json').version")
echo "New version: $VERSION"

# Push commit and tag
echo "Pushing to origin..."
git push origin main
git push origin "v$VERSION"

# Create GitHub Release (triggers release.yml workflow)
echo "Creating GitHub Release..."
gh release create "v$VERSION" \
    --title "$VERSION" \
    --generate-notes

echo ""
echo "Release v$VERSION created!"
echo "The GitHub Actions workflow will now publish to npm and Docker Hub."
echo "Monitor at: https://github.com/hellocoop/mockin/actions"
