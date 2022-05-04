#!/usr/bin/env bash
CURRENT_PATH=$(cd "$(dirname "$0")";pwd)
ANDROID_NDK_HOME=/Users/wadahana/Library/Android/ndk
BUILD_DIR=${CURRENT_PATH}/build
API_VERSION="android-28"
echo "build: $BUILD_DIR"

function build() {
  if [ $1 == "arm" ]; then
    ARCH="armeabi-v7a"
  elif [ $1 == "arm64" ]; then
    ARCH="arm64-v8a"
  elif [ $1 == "x86" ]; then
    ARCH="x86"
  elif [ $1 == "x86_64" ]; then
    ARCH="x86_64"
  fi
  OUTPUT_DIR="${BUILD_DIR}/output"
  BUILD_DIR="${BUILD_DIR}/${ARCH}"
  mkdir -p "${BUILD_DIR}"
  mkdir -p "${OUTPUT_DIR}"
  pushd ${BUILD_DIR}
  cmake -DCMAKE_ANDROID_NDK=${ANDROID_NDK_HOME} \
        -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
        -DANDROID_PLATFORM=${API_VERSION} \
        -DCMAKE_SYSTEM_NAME=Android \
        -DCMAKE_ANDROID_ARCH_ABI=${ARCH} \
        -DCMAKE_INSTALL_PREFIX=${OUTPUT_DIR} \
        ../..
  make VERBOSE=1
  popd
}

if [ $1 == "arm" ]; then
  build "arm"
elif [ $1 == "arm64" ]; then
  build "arm64"
elif [ $1 == "both" ]; then
  build "arm"
  build "arm64"
else
  echo "build.sh [arm|arm64]"
  exit 0
fi

