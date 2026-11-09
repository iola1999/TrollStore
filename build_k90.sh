#!/usr/bin/env bash
# Build TrollStore.app and trollstorehelper (arm64e) for HackiOS on REDMI K90 (annibale).
set -euo pipefail

TS_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${1:-$TS_DIR/build}"
ROOT_DIR="${2:-}"

mkdir -p "$OUT_DIR"

PRIVATE_INC="$TS_DIR/PrivateSDK/include"
PRIVATE_FW="$TS_DIR/PrivateSDK/PrivateFrameworks"
PRIVATE_LIB="$TS_DIR/PrivateSDK/lib"

COMMON_FLAGS=(
    -fobjc-arc
    -O2
    -Wno-deprecated-declarations
    -Wno-unused-function
    -Wno-nullability-completeness
    -DTROLLSTORE_MAIN
    -I"$PRIVATE_INC"
    -I"$TS_DIR/Shared"
    -I"$TS_DIR/TrollStore"
    -I"$TS_DIR/RootHelper"
    -F"$PRIVATE_FW"
    -L"$PRIVATE_LIB"
)

if [[ "$(uname -s)" == "Darwin" ]]; then
    SDK_PATH="$(/usr/bin/xcrun --sdk iphoneos --show-sdk-path)"
    CC=(/usr/bin/xcrun -sdk iphoneos clang -arch arm64e -miphoneos-version-min=26.0 -isysroot "$SDK_PATH")
    SIGN_Mode="codesign"
else
    USERLAND_DIR="${USERLAND_DIR:-$TS_DIR/../hackios-xnu-userland/userland}"
    IOS_DIR="${IOS_DIR:-$TS_DIR/../hackios-xnu-kernel/ios26}"
    CC=(
        clang
        --target=arm64e-apple-ios26.0
        -isysroot "$IOS_DIR/iPhoneOS26.0.sdk"
        -fuse-ld=lld
    )
    SIGN_Mode="ldid"
fi

sign_binary() {
    local bin="$1"
    local ent="$2"
    if [[ "$SIGN_Mode" == "codesign" ]]; then
        /usr/bin/codesign --force --sign - --entitlements "$ent" "$bin"
    elif command -v ldid >/dev/null 2>&1; then
        ldid -S"$ent" "$bin"
    fi
}

echo "[trollstore] Compiling trollstorehelper..."
HELPER_SRCS=(
    "$TS_DIR/RootHelper/main.m"
    "$TS_DIR/RootHelper/uicache.m"
    "$TS_DIR/RootHelper/unarchive.m"
    "$TS_DIR/RootHelper/sign.m"
    "$TS_DIR/RootHelper/jit.m"
    "$TS_DIR/RootHelper/devmode.m"
    "$TS_DIR/Shared/TSUtil.m"
)

"${CC[@]}" "${COMMON_FLAGS[@]}" \
    "${HELPER_SRCS[@]}" \
    -larchive \
    -framework Foundation \
    -framework CoreServices \
    -framework CoreTelephony \
    -framework Security \
    -framework UIKit \
    -framework BackBoardServices \
    -framework FrontBoardServices \
    -framework MobileContainerManager \
    -framework RunningBoardServices \
    -o "$OUT_DIR/trollstorehelper"

sign_binary "$OUT_DIR/trollstorehelper" "$TS_DIR/RootHelper/entitlements.plist"
chmod 0755 "$OUT_DIR/trollstorehelper"

echo "[trollstore] Compiling TrollStore.app..."
APP_BUNDLE="$OUT_DIR/TrollStore.app"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE"

APP_SRCS=(
    "$TS_DIR/TrollStore/main.m"
    "$TS_DIR/TrollStore/TSAppDelegate.m"
    "$TS_DIR/TrollStore/TSSceneDelegate.m"
    "$TS_DIR/TrollStore/TSRootViewController.m"
    "$TS_DIR/TrollStore/TSAppTableViewController.m"
    "$TS_DIR/TrollStore/TSAppInfo.m"
    "$TS_DIR/TrollStore/TSApplicationsManager.m"
    "$TS_DIR/TrollStore/TSInstallationController.m"
    "$TS_DIR/TrollStore/TSSettingsListController.m"
    "$TS_DIR/TrollStore/TSSettingsAdvancedListController.m"
    "$TS_DIR/TrollStore/TSDonateListController.m"
    "$TS_DIR/Shared/TSUtil.m"
    "$TS_DIR/Shared/TSPresentationDelegate.m"
    "$TS_DIR/Shared/TSListControllerShared.m"
)

"${CC[@]}" "${COMMON_FLAGS[@]}" \
    "${APP_SRCS[@]}" \
    -larchive \
    -framework Foundation \
    -framework UIKit \
    -framework CoreGraphics \
    -framework QuartzCore \
    -framework CoreServices \
    -framework CoreTelephony \
    -framework Security \
    -framework UniformTypeIdentifiers \
    -framework Preferences \
    -framework BackBoardServices \
    -framework FrontBoardServices \
    -framework MobileContainerManager \
    -framework MobileIcons \
    -o "$APP_BUNDLE/TrollStore"

cp -R "$TS_DIR/TrollStore/Resources/"* "$APP_BUNDLE/"
cp "$OUT_DIR/trollstorehelper" "$APP_BUNDLE/trollstorehelper"
chmod 0755 "$APP_BUNDLE/TrollStore" "$APP_BUNDLE/trollstorehelper"
sign_binary "$APP_BUNDLE/TrollStore" "$TS_DIR/TrollStore/entitlements.plist"

if [[ -n "$ROOT_DIR" ]]; then
    mkdir -p "$ROOT_DIR/Applications" "$ROOT_DIR/bin"
    rm -rf "$ROOT_DIR/Applications/TrollStore.app"
    cp -R "$APP_BUNDLE" "$ROOT_DIR/Applications/TrollStore.app"
    cp "$OUT_DIR/trollstorehelper" "$ROOT_DIR/bin/trollstorehelper"
    chmod 0755 "$ROOT_DIR/bin/trollstorehelper"
fi

RESUME_TS_DIR="$TS_DIR/../out/ios26-resume/trollstore"
if [[ -d "$TS_DIR/../out/ios26-resume" ]]; then
    mkdir -p "$RESUME_TS_DIR"
    cp "$OUT_DIR/trollstorehelper" "$RESUME_TS_DIR/trollstorehelper"
fi

echo "[trollstore] Built $APP_BUNDLE and $OUT_DIR/trollstorehelper"
