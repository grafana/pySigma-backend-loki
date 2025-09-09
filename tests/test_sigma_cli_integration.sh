#!/bin/sh
set -e

plugin="loki"

# Ensure current environment is up-to-date
poetry install
poetry run pip install sigma-cli==1.1.0rc1

sigma=$(poetry run sigma version)

# Fetch plugin metadata from sigma-cli
# Relies on structured output from sigma-cli
meta=$(poetry run sigma plugin list | grep "^| $plugin" | cat) # Avoid termination due to grep not matching
if [ "$meta" = "" ]; then
  echo "❌ FAIL: Could not find metadata for pySigma-backend-$plugin - check it appears in the plugin directory: https://github.com/SigmaHQ/pySigma-plugin-directory/"
  exit 1
fi
echo "✅ PASS: pySigma-backend-$plugin was found in the plugin list"

# Check that sigma-cli believes the plugin is compatible
compatible=$(echo "$meta" | awk -F "|" '{print $6}' | awk '{$1=$1};1')
force_arg=""
if [ "$compatible" = "no" ]; then
  echo "⚠️  WARN: This version of pySigma-backend-$plugin is not compatible with the latest version of sigma-cli ($sigma) - the plugin directory may require updating: https://github.com/SigmaHQ/pySigma-plugin-directory/"
  force_arg=" --force-install"
else
  echo "✅ PASS: pySigma-backend-$plugin is compatible with the latest version of sigma-cli ($sigma)"
fi

# Check the plugin can be successfully installed
install_logs=$(poetry run sigma plugin install $force_arg "$plugin")
install_status=$(echo "$install_logs" | grep "Successfully installed plugin '$plugin'" | cat)
if [ "$install_status" = "" ]; then
  echo "❌ FAIL: Installing this version of pySigma-backend-$plugin was not successful. The install logs were:"
  echo "$install_logs"
  exit 3
fi
echo "✅ PASS: pySigma-backend-$plugin was successfully installed as a plugin"

# Check the plugin can be used successfully to convert a simple rule
# May need tweaking if the rule is not supported or really requires a pipeline
convert_err=$(poetry run sigma convert -t $plugin --without-pipeline tests/test_sigma_rule.yml 2>&1  | grep "^Error: " | cat)
if [ "$convert_err" != "" ]; then
  echo "❌ FAIL: pySigma-backend-$plugin was not able to convert a simple test rule. The error message was:"
  echo "$convert_err"
  exit 4
fi

echo "✅ PASS: pySigma-backend-$plugin was able to convert a simple test rule"
exit 0

