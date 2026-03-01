#!/bin/bash
set -e
for f in /home/lan/.npm/_npx/8718c3904bb5fece/node_modules/openclaw/dist/gateway-cli-*.js; do
  [ -f "$f" ] || continue
  echo "Patching $f..."
  sed -i 's/const canSkipDevice = sharedAuthOk;/const canSkipDevice = sharedAuthOk || allowControlUiBypass;/' "$f"
  sed -i 's/if (!authOk) {/if (!authOk \&\& !allowControlUiBypass) {/' "$f"
done
echo "Done. Verifying patches..."
grep -c 'allowControlUiBypass' /home/lan/.npm/_npx/8718c3904bb5fece/node_modules/openclaw/dist/gateway-cli-*.js
