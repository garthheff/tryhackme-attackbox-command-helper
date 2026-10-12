# TryHackMe AttackBox Command Helper

Install `tryhackme-attackbox-helper.user.js` in Tampermonkey/Greasemonkey.

## GitHub-hosted menus

1. Put `menus.json` in a public GitHub repository.
2. Open the file on GitHub and copy its **Raw** URL.
3. Replace `MENU_CONFIG_URL` near the top of the userscript with that URL.

The helper downloads the JSON at startup and caches it for 15 minutes. If GitHub is unavailable, it tries the last valid cached copy and then falls back to its built-in menus. Invalid JSON is rejected.

Remote menu keys currently supported are `Files`, `Nmap`, `Gobuster`, `FTP`, `Reverse`, and `Listener`. Each item can be a heading, separator, or command:

```json
{
  "Nmap": [
    { "heading": "TCP scans" },
    {
      "label": "Quick scan",
      "description": "Scan common TCP ports",
      "context": "target",
      "command": "sudo nmap -sV -sC {{targetIp}}"
    }
  ]
}
```

Supported contexts and placeholders:

| Context | Available placeholders |
| --- | --- |
| `target` | `{{targetIp}}`, `{{httpUrl}}`, `{{httpsUrl}}`, `{{ftpUrl}}` |
| `reverse` | `{{attackboxIp}}`, `{{port}}` |
| `listener` | `{{port}}` |
| `attackbox` | `{{attackboxIp}}`, `{{username}}`, `{{password}}` |
| `setPort` | No `command` needed; opens the port prompt |
| `raw` | none required |

For an `attackbox` item, set `requirePassword` to `true` if it needs the password. Remote JSON is treated only as data and is never evaluated as JavaScript.

## Service ports and FTP

The **Gobuster** menu has **Set web wordlist (Gobuster / FFUF)** and **Set DNS / VHost wordlist** options. Enter a preset number or a custom absolute path. Choices persist locally and are shell-quoted in copied commands. Web presets include DIRB common/big, DirBuster small/medium, SecLists common, RAFT small words, and RAFT medium directories. DNS presets include the SecLists top 5,000/20,000/110,000 subdomain lists. These paths were verified on the AttackBox; SecLists is installed under `/usr/share/wordlists/SecLists`.

Templates use `{{wordlist}}` for the selected web list and `{{dnsWordlist}}` for DNS/VHost lists. Do not add quotes around these placeholders: the helper quotes the paths. VHost commands require replacing `TARGET_DOMAIN` with the target's domain.

Set HTTP (80) and HTTPS (443) ports in **Gobuster**, FTP (21) in **FTP**, and SSH (22) in **Files**. Values persist across room visits and are independent of the reverse-shell/listener port. Commands use the current values at click time. SSH and SCP use the SSH setting for the AttackBox; web and FTP commands use the target IP.

Each action requesting AttackBox information clears the saved AttackBox IP, username, and password and reads the information panel again. Target information and port settings are preserved. If refresh fails, the action does not copy commands using old credentials. There is no manual Clear button.

All command templates also support `{{httpPort}}`, `{{httpsPort}}`, `{{ftpPort}}`, and `{{sshPort}}`. For example, `curl {{httpUrl}}/` includes the chosen HTTP port. URLs are based on the room's target IP.

The FTP menu includes interactive connection, anonymous login with lftp, anonymous listing/download with curl, and an Nmap anonymous-access check. Replace `REMOTE_FILE` and `LOCAL_FILE` in the download command. Commands are copied to the clipboard for you to run.

To install this update, open [the raw userscript](https://raw.githubusercontent.com/garthheff/tryhackme-attackbox-command-helper/main/tryhackme-attackbox-helper.user.js) with your userscript manager enabled. Reload the room afterward. JSON changes are checked on page load once the 15-minute cache expires.
