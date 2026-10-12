# TryHackMe AttackBox Command Helper

Install `tryhackme-attackbox-helper.user.js` in Tampermonkey/Greasemonkey.

## GitHub-hosted menus

1. Put `menus.json` in a public GitHub repository.
2. Open the file on GitHub and copy its **Raw** URL.
3. Replace `MENU_CONFIG_URL` near the top of the userscript with that URL.

The helper downloads the JSON at startup and caches it for 15 minutes. If GitHub is unavailable, it tries the last valid cached copy and then falls back to its built-in menus. Invalid JSON is rejected.

Remote menu keys currently supported are `Files`, `Nmap`, `Gobuster`, `Reverse`, and `Listener`. Each item can be a heading, separator, or command:

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
| `target` | `{{targetIp}}` |
| `reverse` | `{{attackboxIp}}`, `{{port}}` |
| `listener` | `{{port}}` |
| `attackbox` | `{{attackboxIp}}`, `{{username}}`, `{{password}}` |
| `setPort` | No `command` needed; opens the port prompt |
| `raw` | none required |

For an `attackbox` item, set `requirePassword` to `true` if it needs the password. Remote JSON is treated only as data and is never evaluated as JavaScript.
