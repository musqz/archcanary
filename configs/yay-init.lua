-- Template for ~/.config/yay/init.lua — yay's own hook filename, hardcoded
-- by yay itself (not archcanary's choice). This file is never copied there
-- automatically by any archcanary install path (AUR package or install.sh):
-- it's your per-user yay config, and the hook is opt-in. Copy it yourself:
--   cp configs/yay-init.lua ~/.config/yay/init.lua      # from a git clone
--   cp /usr/lib/archcanary/yay-init.lua ~/.config/yay/init.lua   # AUR package
-- `archcanary --doctor` prints the exact command for your install and flags
-- an existing copy as outdated when the hooks below have moved on.
--
-- yay 13.0 Lua hooks for the AUR security stack (v11).
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
      local scan = line:gsub('"[^"]*"', ""):gsub("'[^']*'", "")
      if scan:match("|%s*sh") or scan:match("|%s*bash") or scan:match("|%s*zsh")
         or scan:match("|%s*dash") or scan:match("|%s*eval")
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
    local has_shell = line:find("|%s*bash") or line:find("|%s*sh") or line:find("|%s*eval")
    if has_revtr and has_shell then return true end
  end
  return false
end

-- Pattern port (check_pkgbuild_caches Pattern 14): sudo/doas/pkexec invoked
-- from a PKGBUILD or .install scriptlet. build()/package() run as the
-- calling user (package() under fakeroot) and a scriptlet already runs as
-- root -- a real PKGBUILD never needs it, and using it writes outside
-- $pkgdir onto the live system. Anchored to a command position (start of
-- line, or after ";", "&", "|", "$(") with an argument required after it.
-- Comment lines and heredoc bodies are skipped, and quoted spans stripped,
-- so setup instructions (`echo "run: sudo ..."`, `cat <<EOF ... EOF`) don't
-- match. Returns the matched tool name, or nil.
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
      for _, tool in ipairs({ "sudo", "doas", "pkexec" }) do
        if scan:match("^%s*" .. tool .. "%s+%S")
           or scan:match("[;&|]%s*" .. tool .. "%s+%S")
           or scan:match("%$%(%s*" .. tool .. "%s+%S") then
          return tool
        end
      end
    end
  end
  return nil
end

-- Pattern port (check_pkgbuild_caches Pattern 15): a source/patch URL
-- pointing at a forge's merge-request or pull-request diff endpoint. That
-- content is mutable -- the MR/PR can be amended after the PKGBUILD was
-- reviewed. A hash-pinned /commit/<sha>.patch is immutable and NOT matched;
-- comment lines are skipped (linking the upstream MR a vendored patch came
-- from is a common note). Returns the matched URL fragment, or nil.
local function _archcanary_mutable_patch_url(pkgbuild)
  for line in (pkgbuild .. "\n"):gmatch("([^\n]*)\n") do
    if not line:match("^%s*#") then
      local m = line:match("/%-/merge_requests/%d+%.diff")
          or line:match("/%-/merge_requests/%d+%.patch")
          or line:match("/%-/merge_requests/%d+/diffs")
          or line:match("/pull/%d+%.diff")
          or line:match("/pull/%d+%.patch")
          or line:match("/pulls/%d+%.diff")
          or line:match("/pulls/%d+%.patch")
      if m then return m end
    end
  end
  return nil
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

-- Blocks on the real terminal until Enter is pressed, so the verdict above
-- is an explicit checkpoint instead of a line that scrolls off under
-- makepkg/cargo build spam (verified empirically: os.execute's child
-- inherits yay's real stdin/stdout/stderr, so `read` genuinely blocks on
-- the terminal here). Not called on yay.abort() paths -- those already
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
      "curl[^\n]*|[^\n]*bash",
      "curl[^\n]*|[^\n]*sh",
      "wget[^\n]*|[^\n]*bash",
      "wget[^\n]*|[^\n]*sh",

      -- eval + command substitution
      "eval%s+%$%(",
      "eval%s+`",

      -- printf hex/octal obfuscation -> _archcanary_has_printf_hex below

      -- variable-split command reassembly (a=bu; b=n; $a$b)
      "[%l_]+=%a+;%s*[%l_]+=%a+;%s*%$",

      -- base64 decode piped to shell — no alternation in Lua patterns, so
      -- flag/target combos are flattened, same as the curl/wget entries above
      "base64[^\n]*%-%-decode[^\n]*|[^\n]*bash",
      "base64[^\n]*%-%-decode[^\n]*|[^\n]*sh",
      "base64[^\n]*%-%-decode[^\n]*|[^\n]*eval",
      "base64[^\n]*%-d[^\n]*|[^\n]*bash",
      "base64[^\n]*%-d[^\n]*|[^\n]*sh",
      "base64[^\n]*%-d[^\n]*|[^\n]*eval",
    }

    for _, pattern in ipairs(patterns) do
      if pkgbuild:match(pattern) then
        flagged = true
        yay.abort(_archcanary_banner(pkg, "BLOCKED: SUSPICIOUS PATTERN") .. " (" .. pattern .. ")")
      end
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

    _archcanary_pause()
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
