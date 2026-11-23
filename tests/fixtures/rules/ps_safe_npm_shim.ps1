#!/usr/bin/env pwsh
$basedir = Split-Path $MyInvocation.MyCommand.Definition -Parent
$NODE_EXE = "$basedir/node.exe"
$NPM_CLI_JS = "$basedir/node_modules/npm/bin/npm-cli.js"
$NPM_ARGS = $args -join " "
if ($MyInvocation.ExpectingInput) {
  $input | & $NODE_EXE $NPM_CLI_JS $args
} else {
  Invoke-Expression "& `"$NODE_EXE`" `"$NPM_CLI_JS`" $NPM_ARGS"
}
