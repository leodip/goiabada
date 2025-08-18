#!/bin/bash
VERSION="1.2"
BUILD_DATE=$(date +%Y-%m-%d)
GIT_COMMIT=$(git rev-parse --short HEAD)

echo "Version: $VERSION"
echo "Build date: $BUILD_DATE"
echo "Git commit: $GIT_COMMIT"
echo "Current directory: $(pwd)"

cd ../
echo "Now in directory: $(pwd)"

# Build authserver
docker build --progress=plain --no-cache -f ./build/Dockerfile-authserver -t leodip/goiabada:authserver-$VERSION --build-arg version=$VERSION --build-arg buildDate=$BUILD_DATE --build-arg gitCommit=$GIT_COMMIT --no-cache .
docker tag leodip/goiabada:authserver-$VERSION leodip/goiabada:authserver-latest

echo "Authserver image built. Now building the admin console image."

# Build adminconsole
docker build --progress=plain --no-cache -f ./build/Dockerfile-adminconsole -t leodip/goiabada:adminconsole-$VERSION --build-arg version=$VERSION --build-arg buildDate=$BUILD_DATE --build-arg gitCommit=$GIT_COMMIT --no-cache .
docker tag leodip/goiabada:adminconsole-$VERSION leodip/goiabada:adminconsole-latest

docker images

echo "All done."