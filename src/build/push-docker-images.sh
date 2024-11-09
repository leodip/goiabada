#!/bin/bash
VERSION="0.8"

echo "Version: $VERSION"

docker push leodip/goiabada:authserver-$VERSION
docker push leodip/goiabada:authserver-latest

docker push leodip/goiabada:adminconsole-$VERSION
docker push leodip/goiabada:adminconsole-latest