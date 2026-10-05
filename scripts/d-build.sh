#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

repository_name=
container_name=
folder=

dockerfile=Dockerfile

version_suffix=-beta
version_suffix=

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"
case "${key}" in
    --name)
    repository_name="$2"
    container_name="$2"
    shift # past argument
    shift # past value
    ;;
    --folder)
    folder="$2"
    shift # past argument
    shift # past value
    ;;
    --version)
    version="$2"
    shift # past argument
    shift # past value
    ;;
    --dockerfile)
    dockerfile="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ -z "${container_name}" ]]
then
    echo "name not specified"
    exit 1
fi

if [[ -z "${version}" ]]
then
    echo "version not specified"
    exit 1
fi

if [[ -z "${folder}" ]]
then
    echo "folder not specified"
    exit 1
fi

image_version="${version}${version_suffix}"

cd "${folder}"

echo "Creating/using buildx env..."
docker buildx create --name "${repository_name}" --use >/dev/null 2>&1 || docker buildx use "${repository_name}"
echo "Done."

echo "Building the image..."
echo "Building Docker image..."
docker buildx build \
    --builder "${repository_name}" \
    --pull \
    --load \
    --tag "${repository_name}" \
    --build-arg VERSION="${version}" \
    --file "${dockerfile}" \
    .
echo "Done."

echo "Tagging the source image..."
docker tag "${repository_name}" "${repository_name}:${image_version}"
echo "Done."
