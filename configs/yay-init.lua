-- SPDX-License-Identifier: GPL-3.0-only
-- Template for ~/.config/yay/init.lua — yay's own hook filename, hardcoded
-- by yay itself (not archcanary's choice). This file is never copied there
-- automatically by any archcanary install path (AUR package or install.sh):
-- it's your per-user yay config, and the hook is opt-in. Copy it yourself:
--   cp configs/yay-init.lua ~/.config/yay/init.lua      # from a git clone
--   cp /usr/lib/archcanary/yay-init.lua ~/.config/yay/init.lua   # AUR package
-- `archcanary --doctor` prints the exact command for your install and flags
-- an existing copy as outdated when the hooks below have moved on.
--
-- yay 13.0 Lua hooks for the AUR security stack (v16).
-- An offline backstop that runs on every AUR install/upgrade: warns on
-- recently-modified PKGBUILDs and blocks known malicious patterns before
-- build. See docs/my-setup.md, "yay 13.0 integration".
--
-- Version marker above (the "(vN)" suffix) is checked by `--doctor` to
-- detect a stale local copy, since nothing ever overwrites an existing
-- init.lua. Bump it whenever the hooks below change; never touch the text
-- before "(vN)", since --doctor also prefix-matches on that stable part to
-- tell "some archcanary version present" from "never installed".

-- Options
yay.opt.diff_menu   = true
yay.opt.edit_menu   = true    -- lets you review each PKGBUILD before it builds
yay.opt.clean_menu  = true
yay.opt.clean_after = false
yay.opt.sort_by     = "votes"
yay.opt.bottom_up   = false

-- Pause after a CLEAN PKGBUILD scan too? Default false: a clean verdict
-- prints its banner and the build proceeds; a warn verdict stops with a
-- "press Enter to continue" checkpoint (a block aborts the install
-- outright). Set true to pause on every scan -- useful for big builds
-- where even the clean banner scrolls off under compile spam before you
-- can read it.
local ARCHCANARY_PAUSE_ON_CLEAN = false

-- Warn about AUR packages with PKGBUILD modified < 3 days ago
yay.create_autocmd("UpgradeSelect", {
  desc = "flag recently modified AUR upgrades",
  callback = function(event)
    local cutoff = os.time() - (3 * 24 * 60 * 60)
    for _, pkg in ipairs(event.data.upgrades) do
      if pkg.repository == "aur" and pkg.last_modified >= cutoff then
        local hours = math.floor((os.time() - pkg.last_modified) / 3600)
        yay.log.warn(pkg.name .. ": PKGBUILD modified "
                     .. hours .. "h ago — review carefully")
      end
    end
    return { exclude = {}, skip_menu = false }
  end,
})

-- `| <shell>` with the shell name word-anchored -- not followed by another
-- alphanumeric char -- so `| sha256sum` / `| sha512sum` (Chrome extension-id
-- and checksum-verify idioms) is not read as `| sh`. gopher-lua (yay 13's
-- Lua engine, v1.1.2) has NO `%f` frontier pattern, so a "\n" is appended
-- and the anchor is a plain non-alphanumeric class. Do not use `%f` in
-- this file -- it silently parses as a literal `f` under gopher-lua.
local _ARCHCANARY_PIPE_SHELLS = { "bash", "sh", "zsh", "dash", "eval" }
-- wrappers that hand their stdin straight to the shell that follows, so
-- `| sudo bash` / `| env -i sh` is still a pipe-to-shell. A bare command
-- before the shell name (`| grep bash`, `| command -v sh`) is NOT.
local _ARCHCANARY_PIPE_WRAPPERS = { "sudo", "doas", "pkexec", "env", "exec" }
-- one pipe stage's text, taken right after `<wrapper> ` -- true only if it
-- is the wrapper's own glued flags (`-E`, `-i`) or `VAR=val` assignments
-- and then a shell, NOT a whole command whose argument is a shell name
-- (`sudo pacman -S bash`). A detached flag operand (`sudo -u root bash`)
-- also stops the match -- `sudo bash` still hits, and _archcanary_has_priv_esc
-- flags a `sudo -u root` in a build function regardless.
local function _archcanary_wrapped_shell(seg)
  for tok in seg:gmatch("%S+") do
    for _, name in ipairs(_ARCHCANARY_PIPE_SHELLS) do
      if tok == name or tok:match("^" .. name .. "[;|&)<>`]") then
        return true
      end
    end
    if not (tok:match("^%-") or tok:match("^[%a_][%w_]*=")) then
      return false
    end
  end
  return false
end
-- true if a single `|` or `|&` (not the `||` of a fallback) feeds a shell
-- -- directly (`| sh`) or through one privilege/env wrapper (`| sudo sh`),
-- but NOT across a `;`/`&&`/`||` boundary and NOT as a plain command's last
-- argument. Terminator class: space ; | & ) < > backtick, or the appended
-- `\n`. `.`/`/` are excluded so `bash.log` / a path stays out, and
-- `sha256sum` never starts with the word `sh`.
local function _archcanary_pipe_to_shell(s)
  -- blank out `||` (fallback, not a pipe) so a plain `|` scan is safe and
  -- every `|` -- including a second one later on the line -- is checked
  -- (gmatch on a `[^|&]|` anchor would skip an adjacent match).
  s = " " .. s:gsub("||", "  ") .. "\n"
  for _, name in ipairs(_ARCHCANARY_PIPE_SHELLS) do
    if s:find("|&?%s*" .. name .. "[%s;|&)<>`]") then
      return true
    end
  end
  for _, w in ipairs(_ARCHCANARY_PIPE_WRAPPERS) do
    for seg in s:gmatch("|&?%s*" .. w .. "%s+([^|;&]*)") do
      if _archcanary_wrapped_shell(seg) then
        return true
      end
    end
  end
  return false
end

-- Pattern port (check_pkgbuild_caches, archcanary.sh): ANSI-C hex/octal
-- quoting with 3+ chained \xHH/\NNN escapes spelling out a command
-- byte-by-byte, e.g. $'\x63\x75\x72\x6c' for "curl". Lua patterns have no
-- counted repetition ({3,}) so this walks the string by hand, counting
-- consecutive escapes immediately after each literal "$'". A single escape
-- (read -d $'\0', the standard find -print0 idiom) must NOT match — this is
-- the same false positive check_pkgbuild_caches' own re_ansi_c already
-- fixed once (see its comment in archcanary.sh); do not reintroduce it here.
local function _archcanary_has_chained_ansi_c(pkgbuild)
  local pos = 1
  while true do
    local s, e = pkgbuild:find("$'", pos, true)
    if not s then return false end
    local i, run = e + 1, 0
    while true do
      local hx = pkgbuild:match("^\\x%x%x", i)
      local oc = (not hx) and pkgbuild:match("^\\[0-7][0-7]?[0-7]?", i)
      local esc = hx or oc
      if not esc then break end
      run = run + 1
      if run >= 3 then return true end
      i = i + #esc
    end
    pos = e + 1
  end
end

-- Pattern port (check_pkgbuild_caches Pattern 4): printf spelling a command
-- out a byte at a time. A single \xHH/\NNN escape that decodes to a letter
-- or digit is the signal -- ESC and the CSI bytes of a `printf '\033[1m'`
-- colour code decode to neither, and '\x3d\x3d\x3e' = "==>" doesn't either,
-- so coloured build/scriptlet output is exempt (was 246 false positives in
-- a full-AUR scan). Also flags a printf carrying any escape whose output is
-- piped to a shell / eval'd (letters left plain, only punctuation encoded).
local function _archcanary_has_printf_hex(pkgbuild)
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    if line:find("printf", 1, true)
       and (line:match("\\x%x") or line:match("\\[0-7]")) then
      if line:match("\\x3[0-9]") or line:match("\\x4[1-9a-fA-F]")
         or line:match("\\x5[0-9aA]") or line:match("\\x6[1-9a-fA-F]")
         or line:match("\\x7[0-9aA]")
         or line:match("\\0?6[0-7]") or line:match("\\0?7[01]")
         or line:match("\\0?10[1-7]") or line:match("\\0?1[12][0-7]")
         or line:match("\\0?13[0-2]") or line:match("\\0?14[1-7]")
         or line:match("\\0?1[56][0-7]") or line:match("\\0?17[0-2]") then
        return true
      end
      -- output piped to a shell / eval'd. Word-anchored (see
      -- _archcanary_pipe_to_shell) so `| sha256sum` / `| shred` don't count.
      local scan = line:gsub('"[^"]*"', ""):gsub("'[^']*'", "")
      if _archcanary_pipe_to_shell(scan)
         or scan:match("^%s*eval%s") or scan:match("[;&|]%s*eval%s") then
        return true
      end
    end
  end
  return false
end

-- Pattern port: rev/tr piped to a shell — two independent per-line
-- substring checks ANDed together (order-independent, matching
-- check_pkgbuild_caches exactly). Lua has no alternation, so each side is a
-- small set of flat find() calls.
local function _archcanary_has_revtr_pipe_shell(pkgbuild)
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    local has_revtr = line:find("|%s*rev%s") or line:find("|%s*tr%s")
    -- `| tr … | sha256sum -c` is a checksum-verify line, not `| sh`
    if has_revtr and _archcanary_pipe_to_shell(line) then return true end
  end
  return false
end

-- Pattern port: a downloader (curl/wget) at a command position, or a
-- `base64 -d`/`--decode` whose output is piped onward, on a line that then
-- pipes into a shell -- the Atomic Arch campaign's `curl | bash` and the
-- base64-decode-to-shell shape. `| sha256sum` is not matched, nor is a
-- `$curl_result` / `libcurl` substring, nor `base64 -d > f && x | sh`.
-- The decode flag is space-delimited on its left and `d` may sit in a
-- short-flag group (`-d`, `-di`, `-w0 -d`). Whole-line comments are
-- skipped (like _archcanary_has_priv_esc): a `# install: curl … | sh`
-- note copied from an upstream README is common and this hook hard-aborts.
local function _archcanary_has_dl_pipe_shell(pkgbuild)
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    if not line:match("^%s*#") then
      local sl = " " .. line
      local dl_cmd = sl:match("[^%w$]curl[%s|]") or sl:match("[^%w$]wget[%s|]")
      -- a decode flag whose output is piped onward -- a `|` before any
      -- `;`/`&`, with a file/herestring operand or `2>…` allowed between
      local b64 = line:match("base64%s+%-%a*d%a*[^;&|]*|")
               or line:match("base64%s[^;&|]*%s%-%a*d%a*[^;&|]*|")
               or line:match("base64%s[^;&|]*%-%-decode[^;&|]*|")
      if (dl_cmd or b64) and _archcanary_pipe_to_shell(line) then
        return true
      end
    end
  end
  return false
end

-- Pattern port (check_pkgbuild_caches Pattern 14): sudo/doas/pkexec invoked
-- from a PKGBUILD build()/package(), which makepkg runs as the calling user
-- (package() under fakeroot) -- shelling through sudo writes outside $pkgdir
-- onto the live system. PKGBUILD only (the hook never sees the .install).
-- Comment lines (whole-line and trailing) and heredoc bodies are skipped,
-- quoted spans stripped, then the line is split into commands on ; & | ( so
-- a decoy `sudo -u nobody :` can't shield a real `; sudo cp` on the same
-- line. `sudo -u <user>` / `--user` is de-escalation (run a step as another
-- user), not matched -- except `-u root` / `-u 0`, which IS the escape.
-- Returns the tool, or nil.

-- Is this command fragment `sudo -u <user>` / `--user` (run a step AS
-- another user -- de-escalation)? True only when -u is sudo's own option:
-- walk the tokens after `sudo`, skipping leading -flags, and see if -u is
-- the first non-flag (so `sudo tar -u ...` -- tar's -u -- is NOT run-as).
local function _archcanary_runas(frag)
  local rest = frag:match("^%s*sudo%s+(.*)") or frag:match("^%s*doas%s+(.*)")
  if not rest then return false end
  for tok in rest:gmatch("%S+") do
    if tok == "-u" or tok:match("^%-u.") or tok == "--user" or tok:match("^%-%-user=") then
      return true
    elseif not tok:match("^%-") then
      return false
    end
  end
  return false
end
local function _archcanary_runas_root(s)
  s = s .. " "   -- so a trailing `-u root` gets a boundary char (no %f here)
  -- `[^%w_]` (not `%W`) mirrors the bash re_runas_root anchor `[^[:alnum:]_]`
  -- -- Lua's `%w` excludes `_`, so `%W` would match it and mis-flag a
  -- de-escalation to a `root_svc`-style account.
  return s:match("%-u[%s=]*root[^%w_]") or s:match("%-u[%s=]*0[^%w_]")
      or s:match("%-%-user[%s=]*root[^%w_]") or s:match("%-%-user[%s=]*0[^%w_]")
end
local function _archcanary_has_priv_esc(pkgbuild)
  local hd
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    local in_hd = hd ~= nil
    if hd then
      if line:match("^%s*" .. hd .. "%s*$") then hd = nil end
    else
      -- require whitespace before `<<` so a `<<` inside a quoted string
      -- doesn't start a phantom heredoc (mirrors re_heredoc in archcanary.sh)
      local d = line:match("%s<<%-?%s*['\"]?([%a_][%w_]*)")
      if d then hd = d end
    end
    if not in_hd and not line:match("^%s*#") then
      local scan = line:gsub('"[^"]*"', ""):gsub("'[^']*'", "")
                       :gsub("%s#.*", ""):gsub("\t#.*", "")
      -- quote chars (not spans) removed + trailing comment gone: the -u
      -- target survives so `sudo -u "root"` can't hide, but a `# ... -u
      -- root` note can't un-exempt a real `sudo -u builder`.
      local dq = line:gsub("%s#.*", ""):gsub("\t#.*", ""):gsub("[\"']", "")
      local root_ua = _archcanary_runas_root(dq)
      for frag in (scan .. "("):gmatch("([^;&|({]*)[;&|({]") do
        for _, tool in ipairs({ "sudo", "doas", "pkexec" }) do
          if frag:match("^%s*" .. tool .. "%s+%S")
             and not (_archcanary_runas(frag) and not root_ua) then
            return tool
          end
        end
      end
    end
  end
  return nil
end

-- Pattern port (check_pkgbuild_caches Pattern 15): a source/patch URL on a
-- forge's merge-request or pull-request diff endpoint AND that source entry
-- carries no checksum. That diff is mutable -- an MR/PR can be force-pushed
-- after review -- so an unpinned one means makepkg may fetch something no
-- reviewer saw. A checksummed entry is safe (verification fails loudly) and
-- a /commit/<sha>.patch is immutable; neither is matched. Pairs checksums to
-- sources positionally, the way check_pkgbuild_caches does. Returns the
-- matched URL fragment, or nil.

-- Split a PKGBUILD array body into entries (quotes stripped). Accumulates a
-- bare `name=(...)` and every later `name+=(...)` (makepkg concatenates
-- them). Returns nil on a $() substitution or an absent array -- caller
-- treats either as "can't parse". Comments and CRs are dropped. Line-based,
-- not a shell parser: an entry with a literal ")" would truncate it, same
-- as the bash side's awk.
local function _archcanary_pkgb_array(pkgbuild, name)
  local body, grab = nil, false
  for l in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    l = l:gsub("\r", ""):gsub("%s#.*", ""):gsub("^#.*", "")
    if not grab and l:match("^%s*" .. name .. "%+?=%(") then
      grab = true
      l = l:gsub("^%s*" .. name .. "%+?=%(", "")
    end
    if grab then
      local close = l:find(")", 1, true)
      body = (body or "") .. " " .. (close and l:sub(1, close - 1) or l)
      if close then grab = false end
    end
  end
  if not body or body:find("%$%(") then return nil end
  local out = {}
  for tok in body:gmatch("%S+") do
    tok = tok:gsub("^['\"]+", ""):gsub("['\"]+$", "")
    if tok ~= "" and tok ~= "\\" then out[#out + 1] = tok end
  end
  return out
end

local function _archcanary_mutable_patch_url(pkgbuild)
  local re_mr = {
    "/%-/merge_requests/%d+%.diff", "/%-/merge_requests/%d+%.patch",
    "/%-/merge_requests/%d+/diffs", "/pull/%d+%.diff", "/pull/%d+%.patch",
    "/pulls/%d+%.diff", "/pulls/%d+%.patch",
  }
  local function mr_match(s)
    for _, p in ipairs(re_mr) do local m = s:match(p); if m then return m end end
  end
  if not mr_match(pkgbuild) then return nil end
  local seen, mr_seen = {}, false
  for sname in ("\n" .. pkgbuild):gmatch("\n%s*(source[%w_]*)%+?=%(") do
    local srcs = (not seen[sname]) and _archcanary_pkgb_array(pkgbuild, sname)
    seen[sname] = true
    if srcs then
      -- verified[i] only where an integrity array pins index i. If a *sums
      -- array doesn't pair 1:1, leave every entry unpinned (the cautious
      -- call -- a real hash never coincides with an MR-patch URL anyway).
      local suffix, verified = sname:sub(7), {}
      for _, algo in ipairs({ "b2", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ck" }) do
        local sums = _archcanary_pkgb_array(pkgbuild, algo .. "sums" .. suffix)
        if sums and #sums == #srcs then
          for i, v in ipairs(sums) do
            if v ~= "SKIP" and v ~= "" then verified[i] = true end
          end
        end
      end
      for i, e in ipairs(srcs) do
        if mr_match(e) then
          mr_seen = true
          if not verified[i] then return mr_match(e) end
        end
      end
    end
  end
  if mr_seen then return nil end            -- every MR entry was pinned
  -- The URL is in the file but not in any parsed source entry: a comment
  -- (skipped below), or an unparseable array (a $() entry). Line-scan so an
  -- unpinned one still surfaces.
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    if not line:match("^%s*#") then
      local m = mr_match(line)
      if m then return m end
    end
  end
  return nil
end

-- Pattern port (check_pkgbuild_caches Pattern 16): a deceptive character in
-- the HOST of a `url=` value or a `source=` URL entry -- a confusable
-- Cyrillic/Greek/Armenian/fullwidth letter (U+0370-03FF, U+0400-058F,
-- U+FF00-FF5F) that renders like ASCII, or an invisible / direction
-- control (zero-width U+200B-200D / U+2060-2065 / U+FEFF / U+00AD / U+180E
-- / U+E00xx Tags, LRM/RLM U+200E-200F, ALM U+061C, bidi overrides/isolates
-- U+202A-202E / U+2066-2069). gopher-lua strings are byte strings, so each
-- check is a byte class (no %f, no Unicode support). Only the authority
-- (between `://` and the next `/ ? #`) is checked -- a non-ASCII byte in a
-- URL path is left alone. Column-0 `url=` / `source*=(` only; pkgdesc /
-- optdepends / comments / function bodies and an indented in-function
-- `url=` are not scanned -- a non-Latin description or a Persian ZWNJ
-- there is legitimate. Uses _archcanary_pkgb_array so multi-line arrays /
-- trailing comments are handled and local source filenames (no `://`) are
-- skipped. Returns a short label, or nil.
local function _archcanary_url_authority(u)
  u = u:gsub("^.*::", "")            -- name:: rename prefix
  u = u:gsub("^%a[%w+.%-]*://", "")  -- scheme://
  u = u:gsub("[/?#].*$", "")         -- path / query / fragment
  return (u:gsub("^.*@", ""))        -- userinfo
end
local function _archcanary_has_deceptive_unicode(pkgbuild)
  local function bad(s)
    return s:find("[\208-\212][\128-\191]")        -- U+0400-053F Cyrillic (+ Supplement)
        or s:find("\213[\128-\191]") or s:find("\214[\128-\143]")  -- U+0540-058F Armenian
        or s:find("\205[\176-\191]") or s:find("[\206\207][\128-\191]")  -- U+0370-03FF Greek
        or s:find("\239\188[\128-\191]") or s:find("\239\189[\128-\159]")  -- U+FF00-FF5F fullwidth
        or s:find("\226\128[\139-\143\170-\174]")  -- U+200B-200F (zw + LRM/RLM), U+202A-202E
        or s:find("\226\129[\160-\169]")           -- U+2060-2069
        or s:find("\216\156")                      -- U+061C Arabic letter mark
        or s:find("\239\187\191") or s:find("\194\173") or s:find("\225\160\142")  -- U+FEFF, U+00AD, U+180E
        or s:find("\243\160[\128-\135][\128-\191]")  -- U+E00xx Tags block
  end
  local function bad_host(u)
    local h = _archcanary_url_authority(u)
    return h ~= "" and bad(h)
  end
  -- column-0 assignments only -- an indented url= / source=( is a local var
  -- in a function body, not metadata (mirrors the bash side).
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    if line:match("^url%s*=") then
      local v = line:gsub("^url%s*=%s*", ""):gsub("[\"']", ""):match("^%s*(%S*)")
      if v and v ~= "" and bad_host(v) then
        return "look-alike or hidden character in a url=/source= host"
      end
    end
  end
  local seen = {}
  for sname in ("\n" .. pkgbuild):gmatch("\n(source[%l%d_]*)%+?=%(") do
    if not seen[sname] and (sname == "source" or sname:match("^source_[%l%d_]+$")) then
      seen[sname] = true
      local entries = _archcanary_pkgb_array(pkgbuild, sname)
      if entries then
        for _, e in ipairs(entries) do
          if e:find("://", 1, true) and bad_host(e) then
            return "look-alike or hidden character in a url=/source= host"
          end
        end
      end
    end
  end
  return nil
end

-- Pattern port (check_pkgbuild_caches Pattern 17, .install only): a
-- scriptlet that plants or escalates a login path -- wheel/sudoers
-- escalation, or a password set outside an interactive prompt. Real
-- 2026-09-14 aur-general incident (x11-qemu-validation): a compromised
-- maintainer's post_install created a user with a hardcoded password,
-- added it to wheel, and enabled sshd with password auth for instant
-- root-equivalent remote access. .install-only, like the bash side --
-- package() runs under fakeroot, a real PKGBUILD escape needs sudo
-- (_archcanary_has_priv_esc above already covers that).
--
-- Unlike every other port in this file, yay's Lua API hands the hook only
-- the PKGBUILD's own text (event.data.pkgbuild) -- there's no dedicated
-- .install field, so this reads the file straight off disk from
-- event.data.dir (the build directory yay just downloaded, where
-- PKGBUILD/.SRCINFO/.install all live side by side -- "dir" per yay's own
-- doc/lua.md: "the build directory location", same payload shape for
-- AURPostDownload and AURPreInstall), using the PKGBUILD's own `install=`
-- line to find the filename. Returns false (not flagged) if install= is
-- absent, unresolvable, or the file can't be opened -- never fails open
-- into a false abort.
--
-- The Arch Wiki's own PKGBUILD template uses install=$pkgname.install (not
-- a static literal), so a plain no-substitution parse would silently no-op
-- for a large share of real packages -- $pkgname/${pkgname} and
-- $pkgbase/${pkgbase} (the only variables a real install= line commonly
-- interpolates) are resolved from the PKGBUILD's own pkgname=/pkgbase=
-- lines. A split-package pkgname=(...) array is left alone (not string-
-- substituted into "(a"-style garbage) since resolving it correctly needs
-- the actual sub-package being installed, not just PKGBUILD text -- and
-- any other variable, or one that's still unresolved after substitution,
-- makes the whole match fail rather than guess at the wrong filename.
local function _archcanary_install_file(pkgbuild)
  local text = "\n" .. pkgbuild   -- so a match works even when install=/
                                   -- pkgname=/pkgbase= is the file's first line
  local raw = text:match("\ninstall%s*=%s*(%S+)")
  if not raw then return nil end
  raw = raw:gsub("^['\"]", ""):gsub("['\"]$", "")
  if raw:find("$", 1, true) then
    local pkgname = text:match("\npkgname%s*=%s*(%S+)")
    local pkgbase = text:match("\npkgbase%s*=%s*(%S+)")
    if pkgname and not pkgname:find("(", 1, true) then
      raw = raw:gsub("%$%{?pkgname%}?", pkgname)
    end
    if pkgbase and not pkgbase:find("(", 1, true) then
      raw = raw:gsub("%$%{?pkgbase%}?", pkgbase)
    end
  end
  return raw:match("^([%w_.%-]+)$")
end

-- wheel/sudoers escalation: useradd/usermod granting wheel membership (the
-- g/G flag matched anywhere in the short-flag cluster, so -G/-aG/-Ga all
-- hit -- the one-shot `useradd -G wheel -p <hash> name` form of the
-- incident, not just a separate usermod call; wheel matched anywhere in a
-- comma-joined group list, e.g. `-aG docker,wheel` or `-aG wheel,docker`),
-- gpasswd -a <user> wheel, or a NOPASSWD line on the same line as a
-- sudoers/sudoers.d reference with no ;/& between them (a | is allowed, so
-- a `| sudo tee /etc/sudoers` pipeline still matches). Neither function
-- strips quoted spans first (unlike _archcanary_has_priv_esc above) -- a
-- literal `echo "example: usermod -aG wheel testuser"` doc string can
-- false-positive; accepted for now, since this is a warn, not an abort,
-- and the bash side (check_pkgbuild_caches) makes the identical
-- trade-off. Known gap, same as the bash side: a sudoers drop-in with the
-- filename and the NOPASSWD text on separate heredoc lines isn't
-- correlated -- every check in this file is per-line.
local function _archcanary_has_wheel_escalation(line)
  local s = line .. " "   -- guarantee a boundary char after a trailing match
  return s:match("useradd%s.-%-%a*[gG]%a*%s+%S*wheel[^%w_]") ~= nil
      or s:match("usermod%s.-%-%a*[gG]%a*%s+%S*wheel[^%w_]") ~= nil
      or s:match("gpasswd%s+%-a%s+%S+%s+wheel[^%w_]") ~= nil
end
-- Checks every sudoers/NOPASSWD occurrence pair on the line (not just the
-- first of each), so an earlier decoy mention of "sudoers" (e.g. inside an
-- unrelated log message) can't shield a later real pairing -- Lua's find()
-- only ever returns the first hit, unlike the bash side's regex engine,
-- which already tries every position on its own.
local function _archcanary_has_nopasswd_sudoers(line)
  local sud, nop = {}, {}
  for pos in line:gmatch("()sudoers") do sud[#sud + 1] = pos end
  for pos in line:gmatch("()NOPASSWD") do nop[#nop + 1] = pos end
  for _, s in ipairs(sud) do
    for _, n in ipairs(nop) do
      local lo, hi = math.min(s, n), math.max(s, n)
      if not line:sub(lo, hi):find("[;&]") then return true end
    end
  end
  return false
end

-- a login password set outside an interactive prompt: bare chpasswd (a
-- scriptlet has no legitimate reason to ever call it), or a literal
-- echoed/printf'd straight into chpasswd/passwd, optionally through one
-- privilege/env wrapper -- mirrors _archcanary_wrapped_shell/
-- _archcanary_pipe_to_shell's wrapper handling above, targeting
-- chpasswd/passwd instead of a shell. Deliberately excludes
-- `useradd/usermod -p $(...)`-style dynamically generated passwords, same
-- as the bash side -- the one-shot `useradd -G wheel -p <hash>` incident
-- shape is still caught above via wheel alone.
-- Deliberately near-duplicates _archcanary_wrapped_shell/
-- _archcanary_pipe_to_shell above (same token-walk / wrapper-unwrap
-- shape, different target word list) rather than generalizing those --
-- they're already shipped and covered by test_yay_hook_pipe_anchor;
-- reworking them to share this code would mean relocating that pair
-- earlier in the file (both are defined and used well above this point)
-- for a maintainability win, not a correctness one. If a third port ever
-- needs the same shape, unify all three then.
local _ARCHCANARY_PASSWD_TARGETS = { "chpasswd", "passwd" }
local function _archcanary_wrapped_target(seg, targets)
  for tok in seg:gmatch("%S+") do
    for _, name in ipairs(targets) do
      if tok == name or tok:match("^" .. name .. "[;|&)<>`]") then
        return true
      end
    end
    if not (tok:match("^%-") or tok:match("^[%a_][%w_]*=")) then
      return false
    end
  end
  return false
end
-- Terminator includes `<` alongside whitespace so a herestring/redirect
-- form (`chpasswd<<<"user:pass"`, `chpasswd<file`) still counts -- not
-- just the space-delimited `chpasswd < file` shape.
local function _archcanary_has_chpasswd(line)
  return (" " .. line .. " "):find("[;&|%s]chpasswd[%s<]") ~= nil
end
local function _archcanary_pipe_to_passwd(s)
  if not (s:find("echo%s") or s:find("printf%s")) then return false end
  s = " " .. s:gsub("||", "  ") .. "\n"
  for _, name in ipairs(_ARCHCANARY_PASSWD_TARGETS) do
    if s:find("|&?%s*" .. name .. "[%s;|&)<>`]") then return true end
  end
  for _, w in ipairs(_ARCHCANARY_PIPE_WRAPPERS) do
    for seg in s:gmatch("|&?%s*" .. w .. "%s+([^|;&]*)") do
      if _archcanary_wrapped_target(seg, _ARCHCANARY_PASSWD_TARGETS) then
        return true
      end
    end
  end
  return false
end

-- Reads the .install file the PKGBUILD references (if any) straight off
-- disk and scans it line by line, like the bash side. Whole-line comments
-- are skipped. Returns true if it plants/escalates a privileged account.
-- The read is capped (a real .install scriptlet is a few hundred bytes to
-- a few KB) rather than an unbounded f:read("*a") -- this is attacker-
-- controlled input (an arbitrary AUR package's build directory), and the
-- scanner reading it shouldn't itself be the thing that balloons memory
-- or hangs on it.
local function _archcanary_has_backdoor_account(pkgbuild, dir)
  if not dir or dir == "" then return false end
  local install_file = _archcanary_install_file(pkgbuild)
  if not install_file then return false end
  local f = io.open(dir .. "/" .. install_file, "r")
  if not f then return false end
  local content = f:read(262144)
  f:close()
  if not content then return false end
  for line in (content .. "\n"):gmatch("([^\n]*)\n") do
    if not line:match("^%s*#") then
      if _archcanary_has_wheel_escalation(line)
         or _archcanary_has_nopasswd_sudoers(line)
         or _archcanary_has_chpasswd(line)
         or _archcanary_pipe_to_passwd(line) then
        return true
      end
    end
  end
  return false
end

local function _archcanary_config_dir()
  local xdg = os.getenv("XDG_CONFIG_HOME")
  if xdg and xdg ~= "" then return xdg .. "/archcanary" end
  return os.getenv("HOME") .. "/.config/archcanary"
end

local function _archcanary_load_pkg_set(path)
  local set = {}
  local f = io.open(path, "r")
  if not f then return set end
  for line in f:lines() do
    if not line:match("^#") and line:match("%S") then
      set[line] = true
    end
  end
  f:close()
  return set
end

-- Same "pkgname value" companion-file shape as aur_audit_red_dates.txt and
-- aur_audit_red_versions.txt -> name-to-value map. One loader for both, since
-- the format is identical.
local function _archcanary_load_pkg_map(path)
  local map = {}
  local f = io.open(path, "r")
  if not f then return map end
  for line in f:lines() do
    if not line:match("^#") and line:match("%S") then
      local name, value = line:match("^(%S+)%s+(%S+)")
      if name and value then map[name] = value end
    end
  end
  f:close()
  return map
end

-- Extracts "pkgver-pkgrel" from the freshly-downloaded PKGBUILD's raw text,
-- matching wtako's "version" field format (e.g. "0.5.8-2"), entirely offline
-- via string.match. Returns nil -- not a best-effort guess -- for anything
-- that isn't a simple static literal assignment: a pkgver() function
-- (VCS/-git packages compute this dynamically at build time, so a static
-- pkgver= line, if present at all, is just a stale placeholder), a
-- pkgver=/pkgrel= line that itself uses command or variable substitution
-- (e.g. pkgver=$(date +%Y%m%d), pkgver=${_ver} -- not a literal value, and
-- $(...)/${...} would otherwise leak into the captured string verbatim), or
-- a missing/unparseable line. Callers must treat nil as "unknown" and fall
-- back to the unconditional warning -- never fail open.
local function _archcanary_pkgbuild_version(pkgbuild)
  local pkgver, pkgrel, dynamic
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    if line:match("^%s*pkgver%s*%(%s*%)") then
      dynamic = true
    elseif not pkgver and line:match("^pkgver=") then
      if line:find("$", 1, true) then
        dynamic = true
      else
        pkgver = line:match("^pkgver=['\"]([^'\"]+)['\"]") or line:match("^pkgver=(%S+)")
      end
    end
    if not pkgrel and line:match("^pkgrel=") then
      if line:find("$", 1, true) then
        dynamic = true
      else
        pkgrel = line:match("^pkgrel=['\"]([^'\"]+)['\"]") or line:match("^pkgrel=(%S+)")
      end
    end
  end
  if dynamic or not pkgver or not pkgrel then return nil end
  return pkgver .. "-" .. pkgrel
end

local function _archcanary_banner(pkg, verdict)
  local pad = string.rep("-", 10)
  return "ARCHCANARY: " .. pkg .. " # " .. pad .. " " .. verdict .. " " .. pad .. " #"
end

-- Blocks on the real terminal until Enter is pressed, so a warn verdict is
-- an explicit checkpoint instead of a line that scrolls off under
-- makepkg/cargo build spam (verified empirically: os.execute's child
-- inherits yay's real stdin/stdout/stderr, so `read` genuinely blocks on
-- the terminal here). Called only when the scan flagged something (or when
-- ARCHCANARY_PAUSE_ON_CLEAN is set) -- a clean scan just prints its banner
-- and proceeds. Not called on yay.abort() paths -- those already
-- unwind the whole callback, cancelling the operation outright, so there
-- is nothing left to pause. `[ -t 0 ] &&` skips the read entirely whenever
-- stdin isn't an interactive terminal -- piped/redirected stdin (scripted
-- installs, or answers pre-fed to yay's own later prompts) passes through
-- untouched instead of being partly consumed by this prompt.
local function _archcanary_pause()
  os.execute("[ -t 0 ] && read -r -p 'ARCHCANARY: verdict above -- press Enter to continue... '")
end

-- Static pattern check + aur-audit.wtako.net black/red check, combined into
-- one hook (rather than two separate AURPostDownload registrations) so
-- there's a single "clean" confirmation line when nothing is found. Silence
-- alone can't be told apart from "hook never ran"; an explicit clean line
-- can. aur-audit lists are synced by `archcanary --refresh`, already run
-- weekly by archcanary.timer — see docs/my-setup.md.
--
-- AURPostDownload, not AURPreInstall: fires after yay's diff/edit/clean
-- review menus and makepkg --verifysource, so it scans the PKGBUILD as
-- reviewed/edited rather than a stale pre-review copy — still before
-- compatibility checks, PGP prompts, build, and install.
yay.create_autocmd("AURPostDownload", {
  desc = "block known malicious PKGBUILD patterns + aur-audit black/red check",
  callback = function(event)
    local pkg      = event.match
    local pkgbuild = event.data.pkgbuild
    local flagged  = false

    local patterns = {
      "npm install atomic%-lockfile",   -- Atomic Arch campaign wave 1
      "bun install js%-digest",         -- wave 2

      -- curl/wget/base64-decode piped to a shell -> _archcanary_has_dl_pipe_shell

      -- eval + command substitution
      "eval%s+%$%(",
      "eval%s+`",

      -- printf hex/octal obfuscation -> _archcanary_has_printf_hex below

      -- variable-split command reassembly (a=bu; b=n; $a$b)
      "[%l_]+=%a+;%s*[%l_]+=%a+;%s*%$",
    }

    for _, pattern in ipairs(patterns) do
      if pkgbuild:match(pattern) then
        flagged = true
        yay.abort(_archcanary_banner(pkg, "BLOCKED: SUSPICIOUS PATTERN") .. " (" .. pattern .. ")")
      end
    end

    if _archcanary_has_dl_pipe_shell(pkgbuild) then
      flagged = true
      yay.abort(_archcanary_banner(pkg, "BLOCKED: SUSPICIOUS PATTERN") .. " (curl/wget/base64-decode piped to a shell)")
    end
    if _archcanary_has_printf_hex(pkgbuild) then
      flagged = true
      yay.abort(_archcanary_banner(pkg, "BLOCKED: SUSPICIOUS PATTERN") .. " (printf hex/octal obfuscation)")
    end
    if _archcanary_has_chained_ansi_c(pkgbuild) then
      flagged = true
      yay.abort(_archcanary_banner(pkg, "BLOCKED: SUSPICIOUS PATTERN") .. " (ANSI-C chained hex/octal escapes)")
    end
    if _archcanary_has_revtr_pipe_shell(pkgbuild) then
      flagged = true
      yay.abort(_archcanary_banner(pkg, "BLOCKED: SUSPICIOUS PATTERN") .. " (rev/tr piped to shell)")
    end
    -- Warn, don't abort, for these two: both are real risk signals but a
    -- package tripping them may well be fine, and the line-level heuristics
    -- have enough false-positive surface (heredocs, unusual quoting) that a
    -- hard block would be too aggressive. Matches the bash scanner's
    -- "REVIEW" (not "INFECTED") treatment. `flagged` still suppresses the
    -- "CHECKS CLEAN" line and keeps the press-Enter checkpoint.
    local priv_esc = _archcanary_has_priv_esc(pkgbuild)
    if priv_esc then
      flagged = true
      yay.log.warn(_archcanary_banner(pkg, "PRIVILEGE ESCALATION IN PKGBUILD") .. " (" .. priv_esc
                   .. " — build()/package() run unprivileged; review before continuing)")
    end

    local mr_url = _archcanary_mutable_patch_url(pkgbuild)
    if mr_url then
      flagged = true
      yay.log.warn(_archcanary_banner(pkg, "MUTABLE PATCH SOURCE") .. " (" .. mr_url
                   .. ") — an MR/PR diff can change after review; verify before continuing")
    end

    -- Warn, don't abort (same rationale as the two above): a heuristic on
    -- URL bytes, worth surfacing but not worth blocking a build over.
    local unicode_spoof = _archcanary_has_deceptive_unicode(pkgbuild)
    if unicode_spoof then
      flagged = true
      yay.log.warn(_archcanary_banner(pkg, "DECEPTIVE URL CHARACTER") .. " (" .. unicode_spoof
                   .. " — the host isn't the ASCII name it appears to be; compare it byte-for-byte before continuing)")
    end

    -- Warn, don't abort (same rationale as above): a heuristic on .install
    -- text, worth surfacing but not worth blocking a build over. Reads the
    -- .install file itself off disk via event.data.dir (the build
    -- directory -- passed inline below, not assigned to a local `dir`,
    -- since that name is taken below for archcanary's own config
    -- directory) since yay's Lua API doesn't hand the hook the .install
    -- file's content directly.
    if _archcanary_has_backdoor_account(pkgbuild, event.data.dir) then
      flagged = true
      yay.log.warn(_archcanary_banner(pkg, "BACKDOOR ACCOUNT IN INSTALL SCRIPTLET")
                   .. " — creates/escalates a privileged account (wheel/sudoers membership or a"
                   .. " non-interactively-set password); review the .install file before continuing")
    end

    local dir          = _archcanary_config_dir()
    local black        = _archcanary_load_pkg_set(dir .. "/aur_audit_black.txt")
    local red          = _archcanary_load_pkg_set(dir .. "/aur_audit_red.txt")
    local red_versions = _archcanary_load_pkg_map(dir .. "/aur_audit_red_versions.txt")
    local red_dates    = _archcanary_load_pkg_map(dir .. "/aur_audit_red_dates.txt")

    if black[pkg] then
      flagged = true
      yay.abort(_archcanary_banner(pkg, "AUR-AUDIT FLAGGED BLACK (CONFIRMED MALICIOUS)") .. " — https://aur-audit.wtako.net")
    elseif red[pkg] then
      flagged = true
      -- A name-only match would otherwise warn forever, even once a newer
      -- version is rescanned clean (e.g. firefox-pure: flagged red on an old
      -- version, current version already clean on wtako's own site). Exact
      -- version-string match, not vercmp ordering -- deliberately simple.
      -- Any missing piece (versions file not yet refreshed, dynamic
      -- pkgver(), unparseable PKGBUILD) falls through to the original
      -- unconditional wording below.
      local flagged_ver = red_versions[pkg]
      local current_ver = _archcanary_pkgbuild_version(pkgbuild)
      if flagged_ver and current_ver and current_ver ~= flagged_ver then
        local flagged_date = red_dates[pkg]
        local ver_info = flagged_ver .. (flagged_date and (", " .. flagged_date) or "")
        yay.log.warn(_archcanary_banner(pkg, "AUR-AUDIT FLAGGED RED FOR A DIFFERENT VERSION") .. " (" .. ver_info
                     .. ") — installing " .. current_ver
                     .. " — verify at aur-audit.wtako.net if this looks stale")
      else
        yay.log.warn(_archcanary_banner(pkg, "AUR-AUDIT FLAGGED RED (HIGH-RISK, UNCONFIRMED)") .. " — review before continuing")
      end
    end

    if not flagged then
      yay.log.info(_archcanary_banner(pkg, "PKGBUILD CHECKS CLEAN"))
    end

    if flagged or ARCHCANARY_PAUSE_ON_CLEAN then
      _archcanary_pause()
    end
  end,
})

-- Log AUR installs
yay.create_autocmd("PostInstall", {
  desc = "log AUR installs",
  callback = function(event)
    for _, pkg in ipairs(event.data.packages) do
      if pkg.source == "aur" then
        yay.log.info("AUR installed: " .. pkg.name .. " " .. pkg.version)
      end
    end
  end,
})
