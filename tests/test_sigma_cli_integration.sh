#!/bin/sh
set -e

plugin="loki"

# Ensure current environment is up-to-date
poetry install
poetry run pip install sigma-cli

sigma=$(poetry run sigma version)

# Fetch plugin metadata from sigma-cli
# Relies on structured output from sigma-cli
meta=$(poetry run sigma plugin list | grep "^| $plugin")
if [ "$meta" = "" ]; then
  echo "❌ FAIL: Could not find metadata for pySigma-backend-$plugin"
  exit 1
fi
echo "✅ PASS: pySigma-backend-$plugin was found in the plugin list"

# Check that sigma-cli believes the plugin is compatible
compatible=$(echo "$meta" | awk -F "|" '{print $6}' | awk '{$1=$1};1')
if [ "$compatible" = "no" ]; then
  echo "❌ FAIL: This version of pySigma-backend-$plugin is not compatible with the latest version of sigma-cli ($sigma)"
  exit 2
fi
echo "✅ PASS: pySigma-backend-$plugin is compatible with the latest version of sigma-cli ($sigma)"

# Check the plugin can be successfully installed
install=$(poetry run sigma plugin install "$plugin" | grep "Successfully installed plugin '$plugin'")
if [ "$install" = "" ]; then
  echo "❌ FAIL: Installing this version of pySigma-backend-$plugin was not successful"
  exit 3
fi
echo "✅ PASS: pySigma-backend-$plugin was successfully installed as a plugin"

# Check the plugin can be used successfully to convert a simple rule
# May need tweaking if the rule is not supported or really equires a pipeline
convert_err=$(poetry run sigma convert -t $plugin --without-pipeline tests/test_sigma_rule.yml 2>&1  | grep "^Error: " | cat) # Avoid termination due to grep not matching
if [ "$convert_err" != "" ]; then
  echo "❌ FAIL: pySigma-backend-$plugin was not able to convert a simple test rule"
  echo "$convert_err"
  exit 4
fi

echo "✅ PASS: pySigma-backend-$plugin was able to convert a simple test rule"
exit 0

