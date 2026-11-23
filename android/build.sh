#!/bin/bash
set -e
cd "$(dirname "$0")"
TOOLS=$HOME/workspace/tools/android
export JAVA_HOME=$TOOLS/jdk17
export PATH=$JAVA_HOME/bin:$PATH
BT=$TOOLS/sdk/build-tools/34.0.0
AJAR=$TOOLS/sdk/platforms/android-34/android.jar

rm -rf build
mkdir -p build/compiled build/classes build/dex

echo "== compile resources =="
$BT/aapt2 compile --dir res -o build/compiled/res.zip

echo "== link =="
$BT/aapt2 link -o build/unsigned.apk -I "$AJAR" --manifest AndroidManifest.xml build/compiled/res.zip

echo "== javac =="
javac --release 8 -cp "$AJAR" -d build/classes $(find src -name "*.java")

echo "== dex =="
$BT/d8 --lib "$AJAR" --output build/dex build/classes/app/securitysuite/mobile/*.class

echo "== package dex into apk =="
cd build
cp unsigned.apk app.apk
zip -q app.apk classes.dex -j dex/classes.dex 2>/dev/null || (mv dex/classes.dex classes.dex && zip -q app.apk classes.dex)
cd ..

echo "== zipalign =="
$BT/zipalign -f -p 4 build/app.apk build/aligned.apk

echo "== keystore (local sideload signing key) =="
if [ ! -f signing.keystore ]; then
  keytool -genkeypair -keystore signing.keystore -alias securitysuite -keyalg RSA -keysize 2048 -validity 3650 -storepass securitysuite-local -keypass securitysuite-local -dname "CN=SecuritySuite, O=Rahil Sahu, C=IN" >/dev/null 2>&1
fi

echo "== sign =="
$BT/apksigner sign --ks signing.keystore --ks-pass pass:securitysuite-local --key-pass pass:securitysuite-local --out SecuritySuite.apk build/aligned.apk

echo "== verify =="
$BT/apksigner verify --verbose SecuritySuite.apk | head -5
$BT/aapt2 dump badging SecuritySuite.apk | head -3
ls -lh SecuritySuite.apk
